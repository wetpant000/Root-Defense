"""Configuration loading for the agent (System A) and the witness (System B)."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "config"
DATA_DIR = PROJECT_ROOT / "data"
CHAIN_DIR = PROJECT_ROOT / "chain"
WEB_DIR = PROJECT_ROOT / "web"

# Hardhat's well-known development account #0. Only ever valid on the local demo chain.
HARDHAT_DEV_KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

AGENT_DEFAULTS: dict[str, Any] = {
    "agent_id": "web-server-01",
    "witness_url": "http://127.0.0.1:8800",
    "token": "",
    "state_dir": str(DATA_DIR / "agent"),
    "heartbeat_interval": 5.0,
    "poll_interval": 0.5,
    "send_interval": 1.0,
    "sources": [
        {"name": "auth.log", "path": str(DATA_DIR / "demo-logs" / "auth.log")},
        {"name": "app.log", "path": str(DATA_DIR / "demo-logs" / "app.log")},
    ],
    "critical_patterns": [
        "Accepted password for root",
        "Accepted publickey for root",
        "COMMAND=",
        "/etc/shadow",
        "useradd",
        "session opened for user root",
    ],
}

WITNESS_DEFAULTS: dict[str, Any] = {
    "host": "0.0.0.0",
    "port": 8800,
    "token": "",
    "data_dir": str(DATA_DIR / "witness"),
    "silence_threshold": 8.0,
    "anchor_interval": 15.0,
    "retention_days": 180,
    "reporting_hours": 6,
    "chain": {
        "mode": "local",  # "local" (Hardhat) or "quai" (Quai Orchard testnet)
        "local": {
            "rpc": "http://127.0.0.1:8545",
            "private_key": HARDHAT_DEV_KEY,
            "contract": "",
        },
        "quai": {
            "rpc": "https://orchard.rpc.quai.network",
            "private_key": "",
            "contract": "",
            "explorer": "https://orchard.quaiscan.io",
        },
    },
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def load(path: Path, defaults: dict) -> dict:
    if path.exists():
        with open(path) as f:
            return _merge(defaults, yaml.safe_load(f) or {})
    return copy.deepcopy(defaults)


def save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)


def agent_config(path: Path | None = None) -> dict:
    return load(path or CONFIG_DIR / "agent.yaml", AGENT_DEFAULTS)


def witness_config(path: Path | None = None) -> dict:
    return load(path or CONFIG_DIR / "witness.yaml", WITNESS_DEFAULTS)
