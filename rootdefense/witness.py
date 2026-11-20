"""Witness service - runs on System B, off the monitored host.

* accepts only appends, verifying hash chain + forward-secure signatures on arrival
* stores raw log text encrypted at rest (Fernet); only hashes are ever anchored
* raises alarms on silence (missing heartbeats), tamper reports, forks and re-enrollment
* batches entries into Merkle roots and anchors them on-chain (interval + immediately on critical events)
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet

from . import chain as chainmod
from .core import crypto
from .store import Store, row_dict
from .ui import c, log

SEV_ORDER = {"info": 0, "warning": 1, "critical": 2}


class IngestError(Exception):
    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class Witness:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.data_dir = Path(cfg["data_dir"])
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data_dir / "witness.db")
        key_file = self.data_dir / "log-encryption.key"
        if not key_file.exists():
            key_file.write_bytes(Fernet.generate_key())
            key_file.chmod(0o600)
        self.fernet = Fernet(key_file.read_bytes())
        self.chain = chainmod.make_chain(cfg)
        self.chain_info: dict = {}
        self.chain_ok: bool | None = None
        self._anchor_now = threading.Event()
        self._anchor_reason = 0
        self.snapshot_requests: dict[str, str] = {}  # agent_id -> request_id
        self.collect_results: dict[str, dict] = {}  # request_id -> {status, report_id, ...}
        self.reports: dict[str, dict] = {}
        self.running = True
        self.started = time.time()

    # ------------------------------------------------------------------ helpers
    def decrypt(self, blob: bytes | None) -> str | None:
        if blob is None:
            return None
        return self.fernet.decrypt(blob).decode("utf-8")

    def add_event(self, agent_id: str | None, etype: str, severity: str, title: str, detail: dict | None = None,
                  anchor: bool = True) -> int:
        ev = {"agent_id": agent_id, "ts": round(time.time(), 3), "type": etype, "severity": severity, "title": title,
              "detail": detail or {}}
        ev["hash"] = crypto.event_hash(ev)
        eid = self.store.x("INSERT INTO events (agent_id, ts, type, severity, title, detail, hash) VALUES (?,?,?,?,?,?,?)",
                           (agent_id, ev["ts"], etype, severity, title, json.dumps(ev["detail"]), ev["hash"]))
        color = {"critical": c.red, "warning": c.yellow}.get(severity, c.green)
        log("witness", color(f"[{severity.upper()}] {title}"))
        if anchor and severity == "critical":
            self.request_anchor(2)
        return eid

    def request_anchor(self, reason: int) -> None:
        self._anchor_reason = max(self._anchor_reason, reason)
        self._anchor_now.set()

    # ------------------------------------------------------------------ enrollment
    def enroll(self, body: dict) -> dict:
        agent_id = body["agent_id"]
        pk = body["public_key"]
        if len(bytes.fromhex(pk)) != 32:
            raise IngestError(400, "bad public key")
        now = time.time()
        with self.store.tx() as s:
            a = s.db.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            if a is None:
                s.db.execute("INSERT INTO agents (agent_id, hostname, first_seen, last_seen, last_seq, head_hash, expected_pk,"
                             " epoch, sources, status) VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (agent_id, body.get("hostname"), now, now, -1, crypto.GENESIS_HASH, pk, 1,
                              json.dumps(body.get("sources", [])), "online"))
                epoch, start, head = 1, 0, crypto.GENESIS_HASH
            else:
                epoch, start, head = a["epoch"] + 1, a["last_seq"] + 1, a["head_hash"]
                s.db.execute("UPDATE agents SET expected_pk = ?, epoch = ?, hostname = ?, last_seen = ?, status = 'online',"
                             " silent_since = NULL, sources = ? WHERE agent_id = ?",
                             (pk, epoch, body.get("hostname"), now, json.dumps(body.get("sources", [])), agent_id))
            s.db.execute("INSERT INTO epochs VALUES (?,?,?,?,?,?)", (agent_id, epoch, start, pk, now, body.get("reason")))
        if epoch == 1:
            self.add_event(agent_id, "AGENT_ENROLLED", "info", f"Agent {agent_id} enrolled ({body.get('hostname')})",
                           {"public_key": pk}, anchor=False)
        else:
            self.add_event(agent_id, "AGENT_REENROLLED", "critical",
                           f"Agent {agent_id} re-enrolled with a new key - its local state was lost or wiped",
                           {"epoch": epoch, "continues_at_seq": start, "reason": body.get("reason"), "public_key": pk})
        known: dict[str, list[str]] = {}
        for r in self.store.q("SELECT source, line_hash FROM entries WHERE agent_id = ? AND kind = 'log' ORDER BY source, line_no",
                              (agent_id,)):
            known.setdefault(r["source"], []).append(r["line_hash"])
        return {"epoch": epoch, "next_seq": start, "head_hash": head, "known": known}

    # ------------------------------------------------------------------ ingestion
    def ingest(self, agent_id: str, entries: list[dict]) -> dict:
        now = time.time()
        events: list[tuple] = []
        anchor_reason = -1
        reject: str | None = None
        with self.store.tx() as s:
            a = s.db.execute("SELECT * FROM agents WHERE agent_id = ?", (agent_id,)).fetchone()
            if a is None:
                raise IngestError(409, "unknown agent - enroll first")
            last_seq, head, pk, status = a["last_seq"], a["head_hash"], a["expected_pk"], a["status"]
            silent_since = a["silent_since"]
            for e in sorted(entries, key=lambda x: x.get("seq", -1)):
                if e.get("agent_id") != agent_id:
                    raise IngestError(400, "entry agent_id mismatch")
                if e["seq"] <= last_seq:
                    old = s.db.execute("SELECT hash FROM entries WHERE agent_id = ? AND seq = ?", (agent_id, e["seq"])).fetchone()
                    if old and old["hash"] == e.get("hash"):
                        continue  # harmless resend
                    events.append(("CHAIN_FORK", "critical", f"Conflicting entry for seq {e['seq']} rejected (possible rewrite attempt)",
                                   {"seq": e["seq"]}))
                    reject = "conflicting entry for an existing sequence number"
                    break
                chk = crypto.check_link(head, e, last_seq + 1, pk)
                if chk.ok and e["kind"] == "log" and crypto.line_hash(e.get("line", "")) != e.get("line_hash"):
                    chk = crypto.ChainCheck(False, "line text does not match line_hash")
                if not chk.ok:
                    events.append(("INVALID_ENTRY", "critical", f"Rejected entry #{e.get('seq')}: {chk.problem}",
                                   {"seq": e.get("seq"), "problem": chk.problem}))
                    reject = chk.problem or "invalid entry"
                    break
                line_enc = self.fernet.encrypt(e["line"].encode("utf-8")) if e.get("line") is not None else None
                s.db.execute("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             (agent_id, e["seq"], e["ts"], now, e["kind"], e.get("source"), e.get("line_no"), e.get("line_hash"),
                              e["prev_hash"], e["next_pk"], json.dumps(e.get("meta") or {}), e["hash"], e["sig"], line_enc))
                last_seq, head, pk = e["seq"], e["hash"], e["next_pk"]
                meta = e.get("meta") or {}
                if e["kind"] == "tamper":
                    lat = None
                    if meta.get("changed_at") and meta.get("detected_at"):
                        lat = round(meta["detected_at"] - meta["changed_at"], 2)
                    events.append(("TAMPER_DETECTED", "critical",
                                   f"Log tampering on {agent_id} - {e.get('source')}: {_describe_ops(meta.get('ops', []))}",
                                   {"seq": e["seq"], "source": e.get("source"), "ops": meta.get("ops", []),
                                    "changed_at": meta.get("changed_at"), "detected_at": meta.get("detected_at"),
                                    "received_at": round(now, 3), "detection_seconds": lat,
                                    "alarm_seconds": round(now - meta["changed_at"], 2) if meta.get("changed_at") else None}))
                    anchor_reason = max(anchor_reason, 2)
                elif meta.get("critical"):
                    events.append(("CRITICAL_ACTIVITY", "warning",
                                   f"Privileged activity on {agent_id} - {e.get('source')}:{e.get('line_no')}",
                                   {"seq": e["seq"], "source": e.get("source"), "line_no": e.get("line_no"),
                                    "text": (e.get("line") or "")[:200]}))
                    anchor_reason = max(anchor_reason, 1)
            entries_ok = last_seq != a["last_seq"]
            if entries_ok:
                s.db.execute("UPDATE agents SET last_seq = ?, head_hash = ?, expected_pk = ?, last_seen = ?, status = 'online',"
                             " silent_since = NULL WHERE agent_id = ?", (last_seq, head, pk, now, agent_id))
        if entries_ok and status == "silent":
            gap = round(now - (silent_since or now), 1)
            events.append(("AGENT_RECOVERED", "info", f"Agent {agent_id} is reporting again (silent for {gap}s)",
                           {"silent_seconds": gap}))
        for etype, sev, title, detail in events:
            self.add_event(agent_id, etype, sev, title, detail, anchor=etype != "TAMPER_DETECTED")
        if anchor_reason >= 0:
            self.request_anchor(anchor_reason)
        if reject:
            raise IngestError(409, reject)
        out = {"accepted_through": last_seq}
        req = self.snapshot_requests.get(agent_id)
        if req:
            out["snapshot_request"] = req
        return out

    # ------------------------------------------------------------------ monitor (silence detection)
    def monitor_loop(self) -> None:
        threshold = float(self.cfg["silence_threshold"])
        while self.running:
            now = time.time()
            for a in self.store.q("SELECT agent_id, last_seen, last_seq, status FROM agents WHERE status = 'online'"):
                silent_for = now - (a["last_seen"] or now)
                if silent_for > threshold:
                    self.store.x("UPDATE agents SET status = 'silent', silent_since = ? WHERE agent_id = ?",
                                 (a["last_seen"], a["agent_id"]))
                    self.add_event(a["agent_id"], "AGENT_SILENT", "critical",
                                   f"No signed heartbeat from {a['agent_id']} for {silent_for:.1f}s - agent killed or network cut",
                                   {"last_seen": a["last_seen"], "silent_seconds": round(silent_for, 1), "threshold": threshold,
                                    "last_seq": a["last_seq"]})
            time.sleep(0.5)

    # ------------------------------------------------------------------ batcher (Merkle + chain)
    def batcher_loop(self) -> None:
        interval = float(self.cfg["anchor_interval"])
        last_chain_check = 0.0
        while self.running:
            self._anchor_now.wait(timeout=interval)
            reason, self._anchor_reason = max(self._anchor_reason, 0), 0
            self._anchor_now.clear()
            if time.time() - last_chain_check > 10:
                self.refresh_chain_info()
                last_chain_check = time.time()
            try:
                self.anchor_pending(reason)
                if self.chain_ok is False:
                    self.add_event(None, "CHAIN_RESTORED", "info", "Blockchain connection restored", anchor=False)
                self.chain_ok = True
            except Exception as e:  # noqa: BLE001
                if self.chain_ok is not False:
                    self.add_event(None, "CHAIN_UNAVAILABLE", "warning",
                                   f"Cannot anchor to {self.chain.mode} chain - witness keeps collecting ({e})", anchor=False)
                self.chain_ok = False
                time.sleep(2)

    def refresh_chain_info(self) -> dict:
        self.chain_info = self.chain.info()
        return self.chain_info

    def anchor_pending(self, reason: int = 0) -> int:
        written = 0
        for a in self.store.q("SELECT agent_id, last_seq FROM agents"):
            agent_id = a["agent_id"]
            last = self.store.one("SELECT MAX(last_seq) AS m FROM batches WHERE agent_id = ?", (agent_id,))["m"]
            start = -1 if last is None else last
            rows = self.store.q("SELECT seq, hash, received_at FROM entries WHERE agent_id = ? AND seq > ? ORDER BY seq LIMIT 4096",
                                (agent_id, start))
            if not rows:
                continue
            hashes = [r["hash"] for r in rows]
            root = crypto.merkle_root(hashes)
            first_seq, last_seq = rows[0]["seq"], rows[-1]["seq"]
            res = self.chain.anchor(crypto.stream_id(agent_id), root, first_seq, last_seq, len(rows), reason)
            now = time.time()
            info = self.chain_info or {}
            self.store.x("INSERT INTO batches (agent_id, first_seq, last_seq, count, root, reason, created_at, chain_mode, chain_id,"
                         " contract, tx_hash, block_number, chain_index, anchor_latency) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                         (agent_id, first_seq, last_seq, len(rows), root, reason, now, self.chain.mode, info.get("chain_id"),
                          self.chain.contract_address, res["tx_hash"], res["block_number"], res["index"],
                          round(now - rows[0]["received_at"], 3)))
            log("batcher", c.blue(f"Anchored {len(rows):>4} entries #{first_seq}-#{last_seq} of {agent_id} "
                                  f"root {root[:18]}... tx {res['tx_hash'][:18]}... [{chainmod.REASONS.get(reason)}]"))
            written += 1
        written += self._anchor_events()
        return written

    def _anchor_events(self) -> int:
        rows = self.store.q("SELECT e.id, e.agent_id, e.hash FROM events e LEFT JOIN event_anchors x ON x.event_id = e.id "
                            "WHERE x.event_id IS NULL ORDER BY e.id")
        if not rows:
            return 0
        hashes = [r["hash"] for r in rows]
        root = crypto.merkle_root(hashes)
        res = self.chain.anchor(crypto.stream_id("witness", "events"), root, rows[0]["id"], rows[-1]["id"], len(rows), 2)
        now = time.time()
        with self.store.tx() as s:
            for i, r in enumerate(rows):
                s.db.execute("INSERT INTO event_anchors VALUES (?,?,?,?,?,?,?,?,?,?)",
                             (r["id"], root, len(rows), i, res["tx_hash"], res["block_number"], res["index"], self.chain.mode,
                              self.chain.contract_address, now))
        log("batcher", c.blue(f"Anchored {len(rows)} witness event(s) root {root[:18]}..."))
        return 1

    # ------------------------------------------------------------------ audit collection
    def request_snapshot(self, agent_id: str) -> str:
        rid = secrets.token_hex(8)
        self.snapshot_requests[agent_id] = rid
        self.collect_results[rid] = {"status": "waiting", "agent_id": agent_id, "requested_at": time.time()}
        return rid

    def receive_snapshot(self, agent_id: str, request_id: str, files: dict) -> dict:
        from .audit import logs_report

        if self.snapshot_requests.get(agent_id) != request_id:
            raise IngestError(409, "no such snapshot request")
        self.snapshot_requests.pop(agent_id, None)
        report = logs_report(self, agent_id, files, origin="Live snapshot collected from the monitored server")
        self.collect_results[request_id] = {"status": "done", "agent_id": agent_id, "report_id": report["id"]}
        return {"report_id": report["id"]}

    def save_report(self, report: dict) -> dict:
        self.reports[report["id"]] = report
        if len(self.reports) > 50:
            self.reports.pop(next(iter(self.reports)))
        return report

    def start(self) -> None:
        self.refresh_chain_info()
        for target in (self.monitor_loop, self.batcher_loop):
            threading.Thread(target=target, daemon=True, name=target.__name__).start()

    # ------------------------------------------------------------------ read models for the dashboard
    def agents(self) -> list[dict]:
        now = time.time()
        out = []
        for r in self.store.q("SELECT * FROM agents ORDER BY agent_id"):
            d = row_dict(r)
            d["seconds_since_seen"] = round(now - (d["last_seen"] or now), 1)
            d["entries"] = d["last_seq"] + 1
            last_hb = self.store.one("SELECT ts FROM entries WHERE agent_id = ? AND kind = 'heartbeat' ORDER BY seq DESC LIMIT 1",
                                     (d["agent_id"],))
            d["last_heartbeat"] = last_hb["ts"] if last_hb else None
            out.append(d)
        return out

    def entry_view(self, r) -> dict:
        d = row_dict(r)
        if r["line_enc"] is not None:
            d["line"] = self.decrypt(r["line_enc"])
        return d


def _describe_ops(ops: list[dict]) -> str:
    parts = []
    for o in ops:
        if o["type"] == "inserted":
            parts.append(f"line(s) inserted before line {o['before_line']}")
        elif o["type"] == "file_missing":
            parts.append("log file deleted")
        else:
            a, b = o["lines"]
            parts.append(f"line {a} {o['type']}" if a == b else f"lines {a}-{b} {o['type']}")
    return ", ".join(parts) or "content changed"
