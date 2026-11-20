"""Benchmarks for the Evidence criterion: sealing, Merkle and witness-ingestion throughput."""
from __future__ import annotations

import tempfile
import time

from .core import crypto
from .core.config import HARDHAT_DEV_KEY, WITNESS_DEFAULTS
from .ui import c


def _entries(n: int, agent_id: str = "bench-agent") -> tuple[list[dict], str]:
    r = crypto.KeyRatchet()
    pk0 = r.public_hex
    head = crypto.GENESIS_HASH
    out = []
    for i in range(n):
        line = f"Nov 20 10:00:{i % 60:02d} bench sshd[{1000 + i}]: Accepted publickey for deploy from 198.51.100.24 port {40000 + i} ssh2"
        e = {"agent_id": agent_id, "seq": i, "ts": time.time(), "kind": "log", "source": "auth.log", "line_no": i + 1,
             "line_hash": crypto.line_hash(line), "prev_hash": head, "meta": {}}
        r.seal(e)
        e["line"] = line
        head = e["hash"]
        out.append(e)
    return out, pk0


def run(n: int = 5000) -> None:
    from .witness import Witness

    print(c.bold(f"Root-Defense benchmark ({n} log entries)\n"))
    t = time.perf_counter()
    entries, pk0 = _entries(n)
    seal = time.perf_counter() - t
    print(f"  Agent sealing (hash chain + Ed25519 + key ratchet): {n / seal:>10,.0f} entries/s")

    hashes = [e["hash"] for e in entries]
    t = time.perf_counter()
    root = crypto.merkle_root(hashes)
    mk = time.perf_counter() - t
    proof = crypto.merkle_proof(hashes, n // 2)
    ok = crypto.verify_proof(hashes[n // 2], n // 2, n, proof, root)
    print(f"  Merkle root over {n} entries:                       {mk * 1000:>10.1f} ms  (proof size {len(proof)} hashes, verified={ok})")

    with tempfile.TemporaryDirectory() as d:
        cfg = {**WITNESS_DEFAULTS, "data_dir": d, "token": "bench"}
        cfg["chain"] = {"mode": "local", "local": {"rpc": "http://127.0.0.1:1", "private_key": HARDHAT_DEV_KEY, "contract": ""}}
        w = Witness(cfg)
        w.enroll({"agent_id": "bench-agent", "public_key": pk0, "hostname": "bench"})
        t = time.perf_counter()
        for chunk in crypto.iter_chunks(entries, 500):
            w.ingest("bench-agent", list(chunk))
        ing = time.perf_counter() - t
    print(f"  Witness ingestion (verify + encrypt + store):       {n / ing:>10,.0f} entries/s")
    print()
    for interval, label in ((5, "5 s"), (60, "1 min"), (600, "10 min")):
        print(f"  Anchors per day at {label:<6} interval: {86400 // interval:>6,}  (cost/day = anchors x measured fee per tx)")
    print(c.dim("\n  One on-chain transaction commits to every entry in its batch, so cost does not grow with log volume."))
