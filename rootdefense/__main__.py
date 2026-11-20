"""Root-Defense command line.  Usage: ./rd <command> [options]   (./rd --help)"""
from __future__ import annotations

import argparse
import json
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from .core.config import (AGENT_DEFAULTS, CHAIN_DIR, CONFIG_DIR, DATA_DIR, HARDHAT_DEV_KEY, WITNESS_DEFAULTS, agent_config,
                          save, witness_config)
from .ui import c, log

WITNESS_CFG = CONFIG_DIR / "witness.yaml"
AGENT_CFG = CONFIG_DIR / "agent.yaml"

BANNER = r"""
  ____             _          ____        __
 |  _ \ ___   ___ | |_       |  _ \  ___ / _| ___ _ __  ___  ___
 | |_) / _ \ / _ \| __|_____ | | | |/ _ \ |_ / _ \ '_ \/ __|/ _ \
 |  _ < (_) | (_) | ||_____|| |_| |  __/  _|  __/ | | \__ \  __/
 |_| \_\___/ \___/ \__|      |____/ \___|_|  \___|_| |_|___/\___|
        logs the attacker can't erase
"""


def lan_ips() -> list[str]:
    ips = []
    try:
        out = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=3).stdout.split()
        # skip IPv6 and container bridge addresses (e.g. Docker's 172.17.0.1)
        ips = [ip for ip in out if ":" not in ip and not (ip.startswith("172.") and ip.endswith(".0.1"))]
    except Exception:  # noqa: BLE001
        pass
    return ips or ["127.0.0.1"]


# ---------------------------------------------------------------------------- init
def cmd_init_witness(a) -> None:
    if WITNESS_CFG.exists() and not a.force:
        sys.exit(f"{WITNESS_CFG} already exists (use --force to overwrite)")
    cfg = json.loads(json.dumps(WITNESS_DEFAULTS))
    cfg["token"] = secrets.token_urlsafe(24)
    cfg["port"] = a.port
    cfg["chain"]["mode"] = a.chain
    del cfg["data_dir"]
    save(WITNESS_CFG, cfg)
    ip = lan_ips()[0]
    print(c.green(f"Created {WITNESS_CFG.relative_to(CONFIG_DIR.parent)}  (chain mode: {a.chain})"))
    print("\nOn System A (the monitored server) run:\n")
    print(c.bold(f"  ./rd init-agent --witness http://{ip}:{a.port} --token {cfg['token']}"))
    print(f"\nThen start this witness with:  {c.bold('./rd up')}")


def cmd_init_agent(a) -> None:
    if AGENT_CFG.exists() and not a.force:
        sys.exit(f"{AGENT_CFG} already exists (use --force to overwrite)")
    cfg = json.loads(json.dumps(AGENT_DEFAULTS))
    cfg.update({"agent_id": a.agent_id, "witness_url": a.witness.rstrip("/"), "token": a.token})
    del cfg["state_dir"]
    del cfg["sources"]
    sources = [{"name": "auth.log", "path": str(DATA_DIR / "demo-logs" / "auth.log")},
               {"name": "app.log", "path": str(DATA_DIR / "demo-logs" / "app.log")}]
    if a.system_auth_log:
        sources.append({"name": "system-auth.log", "path": "/var/log/auth.log"})
    cfg["sources"] = sources
    save(AGENT_CFG, cfg)
    print(c.green(f"Created {AGENT_CFG.relative_to(CONFIG_DIR.parent)} for agent '{a.agent_id}' -> {a.witness}"))
    print(f"Start it with:  {c.bold('./rd up-agent')}   (demo log traffic + agent)")


# ---------------------------------------------------------------------------- chain
def _hardhat_bin() -> Path:
    p = CHAIN_DIR / "node_modules" / ".bin" / "hardhat"
    if not p.exists():
        sys.exit("Hardhat not installed. Run ./rd setup (or: cd chain && npm install)")
    return p


def _rpc_ready(url: str) -> bool:
    import httpx

    try:
        r = httpx.post(url, json={"jsonrpc": "2.0", "id": 1, "method": "eth_chainId", "params": []}, timeout=1.5)
        return r.status_code == 200 and "result" in r.json()
    except Exception:  # noqa: BLE001
        return False


def start_local_chain(cfg: dict) -> subprocess.Popen | None:
    rpc = cfg["chain"]["local"]["rpc"]
    if _rpc_ready(rpc):
        log("chain", f"Local chain already running at {rpc}")
        return None
    DATA_DIR.mkdir(exist_ok=True)
    logf = open(DATA_DIR / "hardhat.log", "w")
    proc = subprocess.Popen([str(_hardhat_bin()), "node", "--hostname", "127.0.0.1", "--port", rpc.rsplit(":", 1)[-1]],
                            cwd=CHAIN_DIR, stdout=logf, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(60):
        if _rpc_ready(rpc):
            log("chain", c.green(f"Local EVM chain started at {rpc} (chain id 31337)"))
            return proc
        time.sleep(0.5)
    proc.terminate()
    sys.exit("Local chain did not start - see data/hardhat.log")


def _save_contract(mode: str, address: str) -> None:
    import yaml

    raw = yaml.safe_load(WITNESS_CFG.read_text()) if WITNESS_CFG.exists() else {}
    raw.setdefault("chain", {}).setdefault(mode, {})["contract"] = address
    save(WITNESS_CFG, raw)


def ensure_contract(cfg: dict, reset_ok: bool) -> None:
    from .chain import make_chain
    from .store import Store

    ch = make_chain(cfg)
    info = ch.info()
    if info.get("contract_ok"):
        log("chain", f"RootRegistry contract at {ch.contract_address} ({info.get('anchor_count')} anchors on-chain)")
        return
    if cfg["chain"]["mode"] != "local":
        sys.exit("No Quai contract configured. Run: ./rd deploy")
    wdb = Path(cfg["data_dir"]) / "witness.db"
    if wdb.exists() and Store(wdb).one("SELECT COUNT(*) AS n FROM batches")["n"] and not reset_ok:
        sys.exit(c.red("The local chain was restarted, so earlier anchors are gone, but the witness still holds batches that "
                       "point to them.\nStart a clean demo with:  ./rd reset --witness   (or run ./rd up --reset)"))
    res = ch.deploy()
    _save_contract("local", res["address"])
    cfg["chain"]["local"]["contract"] = res["address"]
    log("chain", c.green(f"Deployed RootRegistry at {res['address']}"))


def cmd_deploy(a) -> None:
    from .chain import make_chain

    cfg = witness_config()
    if a.quai:
        cfg["chain"]["mode"] = "quai"
    if cfg["chain"]["mode"] == "quai" and not cfg["chain"]["quai"].get("private_key"):
        sys.exit("Set chain.quai.private_key in config/witness.yaml (a funded Cyprus-1 key from Pelagus).")
    ch = make_chain(cfg)
    log("chain", f"Deploying RootRegistry to {ch.label} ...")
    res = ch.deploy()
    _save_contract(cfg["chain"]["mode"], res["address"])
    log("chain", c.green(f"Deployed at {res['address']}  tx {res.get('tx_hash')}"))
    if ch.explorer_address(res["address"]):
        print(f"Explorer: {ch.explorer_address(res['address'])}")


def cmd_chain(_a) -> None:
    cfg = witness_config()
    proc = start_local_chain(cfg)
    if proc:
        print("Press Ctrl+C to stop the local chain.")
        try:
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()


def cmd_quai_info(_a) -> None:
    from .chain import QuaiChain

    cfg = witness_config()
    info = QuaiChain(cfg["chain"]["quai"]).info()
    for k, v in info.items():
        print(f"  {k:<14} {v}")


# ---------------------------------------------------------------------------- witness
def _run_witness(cfg: dict) -> None:
    import uvicorn

    from .webapp import create_app
    from .witness import Witness

    if not cfg.get("token"):
        sys.exit("No witness config. Run: ./rd init-witness")
    w = Witness(cfg)
    w.start()
    print(c.cyan(BANNER))
    ips = lan_ips()
    log("witness", c.bold(f"Witness listening on port {cfg['port']}  chain: {w.chain.label}"))
    port = cfg["port"]
    for ip in ips:
        log("witness", "  Dashboard:  " + c.bold(f"http://{ip}:{port}"))
    log("witness", f"  Local:      http://127.0.0.1:{cfg['port']}")
    uvicorn.run(create_app(w), host=cfg["host"], port=int(cfg["port"]), log_level="warning")


def cmd_witness(_a) -> None:
    _run_witness(witness_config())


def cmd_up(a) -> None:
    cfg = witness_config()
    if not cfg.get("token"):
        sys.exit("No witness config yet. Run: ./rd init-witness")
    if a.reset:
        _reset_witness(cfg)
    proc = start_local_chain(cfg) if cfg["chain"]["mode"] == "local" else None
    try:
        ensure_contract(cfg, a.reset)
        _run_witness(cfg)
    finally:
        if proc:
            log("chain", "Stopping local chain")
            proc.terminate()


# ---------------------------------------------------------------------------- agent side
def cmd_agent(_a) -> None:
    from .agent import main

    if not AGENT_CFG.exists():
        sys.exit("No agent config. Run: ./rd init-agent --witness http://<witness-ip>:8800 --token <token>")
    main()


def cmd_demo_logs(a) -> None:
    from .demo import generate

    generate(agent_config(), rate=a.rate)


def cmd_up_agent(a) -> None:
    from .agent import Agent
    from .demo import generate

    if not AGENT_CFG.exists():
        sys.exit("No agent config. Run: ./rd init-agent --witness http://<witness-ip>:8800 --token <token>")
    cfg = agent_config()
    for s in cfg["sources"]:
        Path(s["path"]).parent.mkdir(parents=True, exist_ok=True)
    gen = None
    if not a.no_traffic:
        gen = subprocess.Popen([sys.executable, "-m", "rootdefense", "demo-logs", "--quiet"], cwd=CONFIG_DIR.parent,
                               start_new_session=True)
    try:
        Agent(cfg).run()
    finally:
        if gen:
            gen.terminate()


def cmd_attack(a) -> None:
    from .demo import attack

    attack(agent_config(), a.action, line=a.line, text=a.text)


# ---------------------------------------------------------------------------- tools
def cmd_verify_bundle(a) -> None:
    from .audit import verify_bundle
    from .chain import LocalChain, QuaiChain

    b = json.loads(Path(a.file).read_text())
    ch = b["chain"]
    rpc = a.rpc or ch.get("rpc")
    if ch["mode"] == "quai":
        chain = QuaiChain({"rpc": rpc or WITNESS_DEFAULTS["chain"]["quai"]["rpc"], "contract": ch["contract"], "explorer": None})
    else:
        chain = LocalChain({"rpc": rpc or "http://127.0.0.1:8545", "private_key": HARDHAT_DEV_KEY, "contract": ch["contract"]})
    print(c.bold(f"Proof bundle {b['report_id']} - verdict recorded: {b['verdict']}"))
    print(f"Chain: {ch['label']}  contract {ch['contract']}")
    res = verify_bundle(b, chain)
    for r in res["results"]:
        mark = c.green("VERIFIED") if r["ok"] else c.red("FAILED  ")
        failed = [k for k, v in r["checks"].items() if not v]
        print(f"  {mark} {r['source']}:{r['line']:<5} {r['type']:<10} {('failed: ' + ', '.join(failed)) if failed else ''}")
    print(c.bold(f"\n{res['verified']}/{res['total']} findings independently verified against the blockchain."))


def _reset_witness(cfg: dict) -> None:
    d = Path(cfg["data_dir"])
    if d.exists():
        shutil.rmtree(d)
        log("witness", c.yellow(f"Cleared witness data ({d})"))
    import yaml

    if WITNESS_CFG.exists() and cfg["chain"]["mode"] == "local":
        raw = yaml.safe_load(WITNESS_CFG.read_text()) or {}
        raw.setdefault("chain", {}).setdefault("local", {})["contract"] = ""
        save(WITNESS_CFG, raw)
        cfg["chain"]["local"]["contract"] = ""


def cmd_reset(a) -> None:
    if not (a.witness or a.agent):
        sys.exit("Choose what to reset: --witness (System B) and/or --agent (System A)")
    if not a.yes and input("This deletes demo data. Type 'yes' to continue: ").strip() != "yes":
        sys.exit("aborted")
    if a.witness:
        _reset_witness(witness_config())
    if a.agent:
        cfg = agent_config()
        shutil.rmtree(cfg["state_dir"], ignore_errors=True)
        shutil.rmtree(DATA_DIR / "demo-logs", ignore_errors=True)
        log("agent", c.yellow("Cleared agent state and demo logs"))


def cmd_bench(a) -> None:
    from .bench import run

    run(a.entries)


def cmd_status(a) -> None:
    import httpx

    url = a.url or f"http://127.0.0.1:{witness_config()['port']}"
    o = httpx.get(f"{url}/api/v1/overview", timeout=5).json()
    print(c.bold(f"Witness {url}  chain: {o['chain'].get('label')}  block {o['chain'].get('block')}"))
    for ag in o["agents"]:
        st = c.green("ONLINE") if ag["status"] == "online" else c.red("SILENT")
        print(f"  {ag['agent_id']:<18} {st}  entries {ag['entries']:<6} last seen {ag['seconds_since_seen']}s ago")
    t = o["totals"]
    print(f"  entries {t['entries']}  anchored {t['anchored_entries']} in {t['batches']} batches  open alarms {len(o['alarms'])}")


def cmd_setup(_a) -> None:
    root = CONFIG_DIR.parent
    subprocess.run(["bash", str(root / "scripts" / "setup.sh")], check=True)


def main() -> None:
    p = argparse.ArgumentParser(prog="rd", description="Root-Defense - tamper-evident logging with blockchain anchoring")
    sub = p.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name, fn, help_):
        sp = sub.add_parser(name, help=help_, description=help_)
        sp.set_defaults(fn=fn)
        return sp

    add("setup", cmd_setup, "Install dependencies and compile the contract")
    sp = add("init-witness", cmd_init_witness, "[System B] Create witness config and an agent token")
    sp.add_argument("--chain", choices=["local", "quai"], default="local")
    sp.add_argument("--port", type=int, default=8800)
    sp.add_argument("--force", action="store_true")
    sp = add("up", cmd_up, "[System B] Start local chain + deploy contract if needed + witness + dashboard")
    sp.add_argument("--reset", action="store_true", help="wipe witness data and redeploy (clean demo)")
    add("witness", cmd_witness, "[System B] Start only the witness + dashboard")
    add("chain", cmd_chain, "[System B] Start only the local EVM chain")
    sp = add("deploy", cmd_deploy, "[System B] Deploy the RootRegistry contract")
    sp.add_argument("--quai", action="store_true", help="deploy to Quai Orchard instead of the configured mode")
    add("quai-info", cmd_quai_info, "Check Quai Orchard connection, wallet zone and balance")

    sp = add("init-agent", cmd_init_agent, "[System A] Create agent config pointing at the witness")
    sp.add_argument("--witness", required=True, help="e.g. http://192.168.1.20:8800")
    sp.add_argument("--token", required=True)
    sp.add_argument("--agent-id", default="web-server-01")
    sp.add_argument("--system-auth-log", action="store_true", help="also watch /var/log/auth.log (needs read access)")
    sp.add_argument("--force", action="store_true")
    sp = add("up-agent", cmd_up_agent, "[System A] Start demo log traffic + agent")
    sp.add_argument("--no-traffic", action="store_true", help="do not generate demo log lines")
    add("agent", cmd_agent, "[System A] Start only the agent")
    sp = add("demo-logs", cmd_demo_logs, "[System A] Generate realistic demo log traffic")
    sp.add_argument("--rate", type=float, default=1.5, help="higher = slower")
    sp.add_argument("--quiet", action="store_true")
    sp = add("attack", cmd_attack, "[System A] Simulate the attacker")
    sp.add_argument("action", choices=["intrude", "edit", "delete", "kill", "wipe", "truncate"])
    sp.add_argument("--line", type=int, help="target a specific line of auth.log")
    sp.add_argument("--text", help="replacement text for 'edit'")

    sp = add("verify-bundle", cmd_verify_bundle, "Independently verify a downloaded proof bundle against the chain")
    sp.add_argument("file")
    sp.add_argument("--rpc", help="override the RPC URL")
    sp = add("status", cmd_status, "Show witness status")
    sp.add_argument("--url")
    sp = add("bench", cmd_bench, "Measure throughput (sealing, Merkle, witness ingestion)")
    sp.add_argument("--entries", type=int, default=5000)
    sp = add("reset", cmd_reset, "Delete demo data")
    sp.add_argument("--witness", action="store_true")
    sp.add_argument("--agent", action="store_true")
    sp.add_argument("--yes", action="store_true")

    a = p.parse_args()

    def _graceful(*_):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _graceful)  # lets `finally` blocks stop child processes (e.g. the local chain)
    signal.signal(signal.SIGINT, signal.default_int_handler)
    if a.cmd == "demo-logs" and a.quiet:
        import os

        sys.stdout = open(os.devnull, "w")
    a.fn(a)


if __name__ == "__main__":
    main()
