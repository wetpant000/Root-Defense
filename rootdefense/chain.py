"""Blockchain adapters behind one small interface.

* LocalChain  - any EVM JSON-RPC chain (the Hardhat demo node) through web3.py
* QuaiChain   - Quai Network (Orchard testnet) through the official quais SDK (chain/quai.js)

The batcher and the auditor only ever use `Chain`, so switching networks is a config change.
"""
from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

from .core.config import CHAIN_DIR

ARTIFACT = CHAIN_DIR / "build" / "RootRegistry.json"
REASONS = {0: "scheduled", 1: "critical", 2: "alarm"}


class ChainError(RuntimeError):
    pass


def _artifact() -> dict:
    if not ARTIFACT.exists():
        raise ChainError("Contract not compiled. Run: ./rd setup")
    return json.loads(ARTIFACT.read_text())


def _b32(hex_str: str) -> bytes:
    h = hex_str[2:] if hex_str.startswith("0x") else hex_str
    b = bytes.fromhex(h)
    if len(b) != 32:
        raise ValueError("expected 32 bytes")
    return b


class Chain:
    mode = "base"
    label = "Chain"

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.contract_address: str = cfg.get("contract") or ""

    def info(self) -> dict: ...
    def deploy(self) -> dict: ...
    def anchor(self, stream: str, root: str, first_seq: int, last_seq: int, count: int, reason: int) -> dict: ...
    def get_anchors(self, indices: list[int]) -> dict[int, dict]: ...

    def explorer_tx(self, tx_hash: str | None) -> str | None:
        return None

    def explorer_address(self, address: str | None) -> str | None:
        return None


class LocalChain(Chain):
    mode = "local"
    label = "Local EVM (Hardhat) - Quai-compatible contract"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        from web3 import Web3

        self._Web3 = Web3
        self.w3 = Web3(Web3.HTTPProvider(cfg["rpc"], request_kwargs={"timeout": 10}))
        self.acct = self.w3.eth.account.from_key(cfg["private_key"])
        self.abi = _artifact()["abi"]
        self._lock = threading.Lock()

    def _contract(self):
        if not self.contract_address:
            raise ChainError("No contract address configured. Run: ./rd deploy")
        return self.w3.eth.contract(address=self._Web3.to_checksum_address(self.contract_address), abi=self.abi)

    def _send(self, tx: dict) -> Any:
        tx.setdefault("from", self.acct.address)
        tx["nonce"] = self.w3.eth.get_transaction_count(self.acct.address, "pending")
        tx["chainId"] = self.w3.eth.chain_id
        signed = self.acct.sign_transaction(tx)
        h = self.w3.eth.send_raw_transaction(signed.raw_transaction)
        return self.w3.eth.wait_for_transaction_receipt(h, timeout=30)

    def info(self) -> dict:
        try:
            out = {
                "mode": self.mode,
                "label": self.label,
                "connected": self.w3.is_connected(),
                "chain_id": self.w3.eth.chain_id,
                "block": self.w3.eth.block_number,
                "rpc": self.cfg["rpc"],
                "writer": self.acct.address,
                "contract": self.contract_address,
                "contract_ok": False,
                "anchor_count": None,
            }
            if self.contract_address:
                code = self.w3.eth.get_code(self._Web3.to_checksum_address(self.contract_address))
                out["contract_ok"] = len(code) > 0
                if out["contract_ok"]:
                    out["anchor_count"] = self._contract().functions.anchorCount().call()
            return out
        except Exception as e:  # noqa: BLE001 - surfaced to the dashboard
            return {"mode": self.mode, "label": self.label, "connected": False, "rpc": self.cfg["rpc"], "error": str(e),
                    "contract": self.contract_address, "contract_ok": False}

    def deploy(self) -> dict:
        art = _artifact()
        with self._lock:
            c = self.w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
            rc = self._send(c.constructor().build_transaction({"from": self.acct.address}))
        self.contract_address = rc.contractAddress
        return {"address": rc.contractAddress, "tx_hash": rc.transactionHash.hex()}

    def anchor(self, stream, root, first_seq, last_seq, count, reason) -> dict:
        with self._lock:
            c = self._contract()
            tx = c.functions.anchor(_b32(stream), _b32(root), first_seq, last_seq, count, reason).build_transaction(
                {"from": self.acct.address}
            )
            rc = self._send(tx)
        if rc.status != 1:
            raise ChainError("anchor transaction reverted")
        index = None
        for ev in c.events.Anchored().process_receipt(rc):
            index = int(ev.args["index"])
        tx_hash = rc.transactionHash.hex()
        return {"tx_hash": tx_hash if tx_hash.startswith("0x") else "0x" + tx_hash,
                "block_number": rc.blockNumber, "index": index}

    def get_anchors(self, indices: list[int]) -> dict[int, dict]:
        c = self._contract()
        out = {}
        for i in indices:
            a = c.functions.getAnchor(i).call()
            out[i] = {
                "streamId": "0x" + a[0].hex(), "root": "0x" + a[1].hex(), "firstSeq": a[2], "lastSeq": a[3],
                "count": a[4], "reason": a[5], "timestamp": a[6], "blockNumber": a[7],
            }
        return out


class QuaiChain(Chain):
    mode = "quai"
    label = "Quai Network - Orchard testnet"

    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self._lock = threading.Lock()

    def _call(self, req: dict, timeout: float = 180) -> dict:
        req = {"rpc": self.cfg["rpc"], **req}
        try:
            p = subprocess.run(
                ["node", str(CHAIN_DIR / "quai.js")], input=json.dumps(req), capture_output=True, text=True,
                timeout=timeout, cwd=str(CHAIN_DIR),
            )
        except subprocess.TimeoutExpired as e:
            raise ChainError(f"Quai request timed out ({req['cmd']})") from e
        line = (p.stdout or "").strip().splitlines()
        if not line:
            raise ChainError(f"Quai bridge failed: {p.stderr.strip()[:300]}")
        out = json.loads(line[-1])
        if not out.get("ok"):
            raise ChainError(out.get("error", "unknown Quai error"))
        return out

    def info(self) -> dict:
        base = {"mode": self.mode, "label": self.label, "rpc": self.cfg["rpc"], "contract": self.contract_address,
                "contract_ok": bool(self.contract_address), "explorer": self.cfg.get("explorer")}
        try:
            r = self._call({"cmd": "info", "privateKey": self.cfg.get("private_key") or None}, timeout=45)
            base.update({"connected": True, "chain_id": int(r["chainId"]), "block": r["block"],
                         "writer": r.get("address"), "zone": r.get("zone"), "balance": r.get("balance")})
            if self.contract_address:
                base["anchor_count"] = self._call({"cmd": "count", "contract": self.contract_address}, timeout=45)["count"]
        except Exception as e:  # noqa: BLE001
            base.update({"connected": False, "error": str(e)})
        return base

    def deploy(self) -> dict:
        with self._lock:
            r = self._call({"cmd": "deploy", "privateKey": self.cfg["private_key"]})
        self.contract_address = r["address"]
        return {"address": r["address"], "tx_hash": r.get("txHash")}

    def anchor(self, stream, root, first_seq, last_seq, count, reason) -> dict:
        with self._lock:
            r = self._call({"cmd": "anchor", "privateKey": self.cfg["private_key"], "contract": self.contract_address,
                            "streamId": stream, "root": root, "firstSeq": first_seq, "lastSeq": last_seq,
                            "count": count, "reason": reason})
        return {"tx_hash": r["txHash"], "block_number": r["blockNumber"], "index": r["index"]}

    def get_anchors(self, indices: list[int]) -> dict[int, dict]:
        if not indices:
            return {}
        r = self._call({"cmd": "getMany", "contract": self.contract_address, "indices": indices})
        return {int(k): v for k, v in r["anchors"].items()}

    def explorer_tx(self, tx_hash):
        return f"{self.cfg.get('explorer')}/tx/{tx_hash}" if tx_hash and self.cfg.get("explorer") else None

    def explorer_address(self, address):
        return f"{self.cfg.get('explorer')}/address/{address}" if address and self.cfg.get("explorer") else None


def make_chain(witness_cfg: dict) -> Chain:
    mode = witness_cfg["chain"]["mode"]
    if mode == "quai":
        return QuaiChain(witness_cfg["chain"]["quai"])
    if mode == "local":
        return LocalChain(witness_cfg["chain"]["local"])
    raise ChainError(f"unknown chain mode {mode!r}")
