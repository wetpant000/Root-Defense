"""Root-Defense agent - runs on the monitored server (System A).

For every new log line it builds a hash-chained, forward-secure signed entry and streams it to the
off-host witness within about a second. It also:
  * sends a signed heartbeat every few seconds (silence => alarm on the witness),
  * re-checks already-sent lines and reports any edit/delete/insert immediately (signed "tamper" entry),
  * answers the auditor's request for a snapshot of the current log files.

Local state (data/agent) is deliberately treated as untrusted: if an attacker wipes it, the agent
re-enrolls and the witness still holds everything that was already sent.
"""
from __future__ import annotations

import json
import os
import signal
import socket
import sqlite3
import sys
import threading
import time
from difflib import SequenceMatcher
from pathlib import Path

import httpx

from .core import crypto
from .core.config import agent_config
from .ui import c, log


class SourceWatcher:
    """Tracks one log file: finds appended lines and detects changes to lines already sent."""

    def __init__(self, name: str, path: str, known: list[str]):
        self.name = name
        self.path = Path(path)
        self.known: list[str] = list(known)  # authentic line hashes, in order, as recorded by the witness
        self._sig: tuple | None = None
        self._cur: list[str] = []
        self._cur_text: list[str] = []
        self.last_report: tuple = ()
        self.polled = False

    def _read(self) -> tuple[list[str], list[str], float | None]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return [], [], None
        sig = (st.st_ino, st.st_size, st.st_mtime_ns)
        if sig != self._sig:
            data = self.path.read_bytes()
            parts = data.split(b"\n")[:-1]  # only complete lines
            self._cur_text = [p.decode("utf-8", "replace").rstrip("\r") for p in parts]
            self._cur = [crypto.line_hash(t) for t in self._cur_text]
            self._sig = sig
        return self._cur, self._cur_text, st.st_mtime

    def poll(self) -> tuple[list[tuple[int, str]], list[dict], float | None]:
        cur, text, mtime = self._read()
        known = self.known
        n = len(known)
        if len(cur) >= n and cur[:n] == known:
            new = [(n + 1 + k, text[n + k]) for k in range(len(cur) - n)]
            return new, [], mtime

        new: list[tuple[int, str]] = []
        ops: list[dict] = []
        for tag, i1, i2, j1, j2 in SequenceMatcher(None, known, cur, autojunk=False).get_opcodes():
            if tag == "equal":
                continue
            if tag == "insert" and i1 == n:
                new.extend((n + 1 + k, text[j1 + k]) for k in range(j2 - j1))
            elif tag == "replace":
                # Same number of lines: modified. Otherwise the block was rewritten; the auditor pairs
                # the lines exactly (it holds the original text, the agent only holds hashes).
                kind = "modified" if i2 - i1 == j2 - j1 else "rewritten"
                ops.append({"type": kind, "lines": [i1 + 1, i2], "now_at": [j1 + 1, j2]})
            elif tag == "delete":
                ops.append({"type": "deleted", "lines": [i1 + 1, i2]})
            elif tag == "insert":
                ops.append({"type": "inserted", "before_line": i1 + 1, "now_at": [j1 + 1, j2]})
        if mtime is None and n:
            ops = [{"type": "file_missing", "lines": [1, n]}]
        return new, ops, mtime

    def snapshot(self) -> str | None:
        try:
            return self.path.read_text("utf-8", "replace")
        except FileNotFoundError:
            return None


class Agent:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.agent_id: str = cfg["agent_id"]
        self.state_dir = Path(cfg["state_dir"])
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.state_dir / "local.db")
        # Overwrite freed pages so a discarded ratchet key does not linger in the database file.
        self.db.execute("PRAGMA secure_delete = ON")
        self.db.execute("CREATE TABLE IF NOT EXISTS outbox (seq INTEGER PRIMARY KEY, body TEXT NOT NULL, sent INTEGER DEFAULT 0)")
        self.db.execute("CREATE TABLE IF NOT EXISTS lines (source TEXT, line_no INTEGER, line_hash TEXT, PRIMARY KEY(source, line_no))")
        self.db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK (id = 1), agent_id TEXT, "
                        "private_key TEXT, next_seq INTEGER, head TEXT)")
        self.db.commit()
        self.http = httpx.Client(base_url=cfg["witness_url"].rstrip("/"), timeout=4.0,
                                 headers={"X-RD-Token": cfg.get("token", ""), "User-Agent": "root-defense-agent/1.0"})
        self.patterns = [p.lower() for p in cfg.get("critical_patterns", [])]
        self.ratchet: crypto.KeyRatchet | None = None
        self.seq = 0
        self.head = crypto.GENESIS_HASH
        self.watchers: list[SourceWatcher] = []
        self.started = time.time()
        self.online = None
        self.running = True

    # ------------------------------------------------------------------ state
    def _save_state(self) -> None:
        """Persist the ratchet key and chain head. Called inside the same transaction as the outbox
        insert, so a crash can never leave a sealed entry without the key that follows it."""
        self.db.execute("INSERT OR REPLACE INTO state VALUES (1, ?, ?, ?, ?)",
                        (self.agent_id, self.ratchet.export_private(), self.seq, self.head))

    def _load_state(self) -> bool:
        st = self.db.execute("SELECT agent_id, private_key, next_seq, head FROM state WHERE id = 1").fetchone()
        if not st or st[0] != self.agent_id:
            return False
        self.ratchet = crypto.KeyRatchet.from_private_hex(st[1])
        self.seq, self.head = st[2], st[3]
        known: dict[str, list[str]] = {}
        for src, h in self.db.execute("SELECT source, line_hash FROM lines ORDER BY source, line_no"):
            known.setdefault(src, []).append(h)
        self._make_watchers(known)
        return True

    def _make_watchers(self, known: dict[str, list[str]]) -> None:
        self.watchers = [SourceWatcher(s["name"], s["path"], known.get(s["name"], [])) for s in self.cfg["sources"]]

    def enroll(self, reason: str) -> None:
        """Register a fresh ratchet key with the witness and continue the chain from the witness's head."""
        self.ratchet = crypto.KeyRatchet()
        body = {"agent_id": self.agent_id, "hostname": socket.gethostname(), "public_key": self.ratchet.public_hex,
                "reason": reason, "sources": [s["name"] for s in self.cfg["sources"]]}
        while self.running:
            try:
                r = self.http.post("/api/v1/enroll", json=body)
                if r.status_code == 401:
                    log("agent", c.red("Witness rejected the token. Check 'token' in config/agent.yaml."))
                    sys.exit(2)
                r.raise_for_status()
                break
            except httpx.HTTPError as e:
                log("agent", c.yellow(f"Witness unreachable ({e.__class__.__name__}); retrying enrollment..."))
                time.sleep(2)
        res = r.json()
        self.seq, self.head = res["next_seq"], res["head_hash"]
        self.db.execute("DELETE FROM outbox")
        self.db.execute("DELETE FROM lines")
        for src, hashes in res.get("known", {}).items():
            self.db.executemany("INSERT INTO lines VALUES (?,?,?)", [(src, i + 1, h) for i, h in enumerate(hashes)])
        self._save_state()
        self.db.commit()
        self._make_watchers(res.get("known", {}))
        log("agent", c.green(f"Enrolled with witness as '{self.agent_id}' (epoch {res['epoch']}, continuing at seq {self.seq})"))

    # ------------------------------------------------------------------ entries
    def _seal(self, kind: str, source: str | None = None, line_no: int | None = None, line: str | None = None,
              meta: dict | None = None) -> dict:
        e = {"agent_id": self.agent_id, "seq": self.seq, "ts": round(time.time(), 3), "kind": kind, "source": source,
             "line_no": line_no, "line_hash": crypto.line_hash(line) if line is not None else None,
             "prev_hash": self.head, "meta": meta or {}}
        self.ratchet.seal(e)
        if line is not None:
            e["line"] = line  # sent to the witness (encrypted at rest there); never anchored on-chain
        self.seq += 1
        self.head = e["hash"]
        # One atomic commit: entry + line record + new ratchet key + chain head.
        self.db.execute("INSERT INTO outbox (seq, body) VALUES (?, ?)", (e["seq"], json.dumps(e)))
        if kind == "log":
            self.db.execute("INSERT OR REPLACE INTO lines VALUES (?,?,?)", (source, line_no, e["line_hash"]))
        self._save_state()
        self.db.commit()
        return e

    def _scan(self) -> None:
        for w in self.watchers:
            new, ops, mtime = w.poll()
            if ops:
                # Re-read once so a file caught in the middle of being rewritten isn't misreported.
                time.sleep(0.15)
                new, ops, mtime = w.poll()
            for line_no, text in new:
                critical = any(p in text.lower() for p in self.patterns)
                self._seal("log", w.name, line_no, text, {"critical": True} if critical else {})
                w.known.append(crypto.line_hash(text))
                tag = c.red("CRITICAL") if critical else c.dim("log")
                log("agent", f"{c.cyan('#' + str(self.seq - 1)):>8} {tag} {w.name}:{line_no}  {c.dim(text[:90])}")
            fp = tuple(json.dumps(o, sort_keys=True) for o in ops)
            if ops and fp != w.last_report:
                w.last_report = fp
                detected = time.time()
                # Latency is only meaningful for a change we saw happen; tampering found at start-up
                # (e.g. after the agent was killed) is reported without a misleading timing.
                live = w.polled and mtime is not None
                meta = {"ops": ops, "detected_at": round(detected, 3), "changed_at": round(mtime, 3) if live else None,
                        "found_at_startup": not w.polled, "authentic_lines": len(w.known)}
                self._seal("tamper", w.name, None, None, meta)
                when = f"{detected - mtime:.2f}s after the change" if live else "on start-up (changed while the agent was down)"
                log("agent", c.red(f"TAMPERING DETECTED in {w.name}: {self._describe(ops)} - reported {when}"))
            elif not ops:
                w.last_report = ()
            w.polled = True

    @staticmethod
    def _describe(ops: list[dict]) -> str:
        parts = []
        for o in ops:
            if o["type"] == "inserted":
                parts.append(f"lines inserted before line {o['before_line']}")
            else:
                a, b = o["lines"]
                parts.append(f"{o['type']} line{'s' if b > a else ''} {a}{'-' + str(b) if b > a else ''}")
        return ", ".join(parts)

    def _heartbeat(self) -> None:
        self._seal("heartbeat", meta={"uptime": round(time.time() - self.started, 1),
                                      "lines": {w.name: len(w.known) for w in self.watchers}})

    def _send(self) -> None:
        rows = self.db.execute("SELECT seq, body FROM outbox WHERE sent = 0 ORDER BY seq LIMIT 500").fetchall()
        try:
            r = self.http.post("/api/v1/entries", json={"agent_id": self.agent_id,
                                                        "entries": [json.loads(b) for _, b in rows]})
        except httpx.HTTPError as e:
            if self.online is not False:
                log("agent", c.yellow(f"Witness unreachable ({e.__class__.__name__}) - buffering entries locally"))
            self.online = False
            return
        if r.status_code == 409:
            log("agent", c.yellow(f"Witness does not recognise our chain ({r.json().get('detail')}); re-enrolling"))
            self.enroll("witness_out_of_sync")
            return
        if r.status_code == 401:
            log("agent", c.red("Witness rejected the token"))
            return
        if r.status_code >= 400:
            log("agent", c.red(f"Witness error {r.status_code}: {r.text[:200]}"))
            return
        if self.online is not True:
            log("agent", c.green(f"Connected to witness {self.cfg['witness_url']}"))
        self.online = True
        res = r.json()
        self.db.execute("UPDATE outbox SET sent = 1 WHERE seq <= ?", (res["accepted_through"],))
        self.db.execute("DELETE FROM outbox WHERE sent = 1 AND seq < ?", (res["accepted_through"] - 1000,))
        self.db.commit()
        if res.get("snapshot_request"):
            self._snapshot(res["snapshot_request"])

    def _snapshot(self, request_id: str) -> None:
        files = {w.name: w.snapshot() for w in self.watchers}
        try:
            self.http.post("/api/v1/snapshot", json={"agent_id": self.agent_id, "request_id": request_id, "files": files},
                           timeout=15)
            log("agent", c.blue(f"Auditor requested the current log files - snapshot sent ({len(files)} files)"))
        except httpx.HTTPError as e:
            log("agent", c.yellow(f"Could not send snapshot: {e}"))

    # ------------------------------------------------------------------ main loop
    def run(self) -> None:
        (self.state_dir / "agent.pid").write_text(str(os.getpid()))
        if threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGTERM, lambda *_: setattr(self, "running", False))
            signal.signal(signal.SIGINT, signal.default_int_handler)  # Ctrl+C works even when started in the background
        log("agent", c.bold(f"Root-Defense agent '{self.agent_id}' starting -> witness {self.cfg['witness_url']}"))
        for s in self.cfg["sources"]:
            log("agent", f"  watching {c.cyan(s['name'])}  {c.dim(s['path'])}")
            p = Path(s["path"])
            if p.exists() and not os.access(p, os.R_OK):
                log("agent", c.red(f"Cannot read {p}. Fix: sudo usermod -aG adm $USER  (then log out and back in)"))
                sys.exit(2)
            if not p.exists() and not self.cfg.get("demo_traffic", True):
                log("agent", c.yellow(f"{p} does not exist yet. Is rsyslog running?  sudo service rsyslog start"))
        if not self._load_state():
            # The witness decides whether this is a first start or a re-enrollment after state loss.
            self.enroll("no_local_state")
        hb = float(self.cfg["heartbeat_interval"])
        last_hb = last_send = 0.0
        try:
            while self.running:
                now = time.time()
                self._scan()
                if now - last_hb >= hb:
                    self._heartbeat()
                    last_hb = now
                if now - last_send >= float(self.cfg["send_interval"]):
                    self._send()
                    last_send = now
                time.sleep(float(self.cfg["poll_interval"]))
        except KeyboardInterrupt:
            pass
        finally:
            log("agent", "stopping")
            try:
                (self.state_dir / "agent.pid").unlink()
            except FileNotFoundError:
                pass


def main(config_path: str | None = None) -> None:
    Agent(agent_config(Path(config_path) if config_path else None)).run()
