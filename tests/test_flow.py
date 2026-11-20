"""End-to-end flow on the witness with an in-memory chain: ingest -> anchor -> tamper -> audit."""
import time

import pytest

from rootdefense.audit import build_bundle, history_report, logs_report, verify_bundle
from rootdefense.core import crypto
from rootdefense.core.config import HARDHAT_DEV_KEY, WITNESS_DEFAULTS
from rootdefense.witness import IngestError, Witness


class FakeChain:
    mode, label = "local", "Fake chain"

    def __init__(self):
        self.anchors = []
        self.contract_address = "0xFAKE"

    def info(self):
        return {"mode": self.mode, "chain_id": 1, "contract_ok": True}

    def anchor(self, stream, root, first_seq, last_seq, count, reason):
        self.anchors.append({"streamId": stream, "root": root, "firstSeq": first_seq, "lastSeq": last_seq, "count": count,
                             "reason": reason, "timestamp": int(time.time()), "blockNumber": len(self.anchors)})
        return {"tx_hash": "0x" + "ab" * 32, "block_number": len(self.anchors), "index": len(self.anchors) - 1}

    def get_anchors(self, indices):
        return {i: self.anchors[i] for i in indices if i < len(self.anchors)}

    def explorer_tx(self, _):
        return None

    def explorer_address(self, _):
        return None


@pytest.fixture
def witness(tmp_path):
    cfg = {**WITNESS_DEFAULTS, "data_dir": str(tmp_path), "token": "t"}
    cfg["chain"] = {"mode": "local", "local": {"rpc": "http://127.0.0.1:1", "private_key": HARDHAT_DEV_KEY, "contract": ""}}
    w = Witness(cfg)
    w.chain = FakeChain()
    return w


def make_entries(ratchet, lines, start_seq=0, head=crypto.GENESIS_HASH, source="auth.log", start_line=1):
    out = []
    for i, line in enumerate(lines):
        e = {"agent_id": "srv", "seq": start_seq + i, "ts": time.time(), "kind": "log", "source": source,
             "line_no": start_line + i, "line_hash": crypto.line_hash(line), "prev_hash": head, "meta": {}}
        ratchet.seal(e)
        e["line"] = line
        head = e["hash"]
        out.append(e)
    return out, head


def test_full_flow(witness):
    r = crypto.KeyRatchet()
    witness.enroll({"agent_id": "srv", "public_key": r.public_hex, "hostname": "h"})
    lines = [f"line {i}" for i in range(10)]
    entries, head = make_entries(r, lines)
    assert witness.ingest("srv", entries)["accepted_through"] == 9
    assert witness.anchor_pending() >= 1

    rep = history_report(witness, "srv")
    assert rep["verdict"] == "GENUINE", rep["issues"]

    # untouched file -> genuine
    rep = logs_report(witness, "srv", {"auth.log": "\n".join(lines) + "\n"}, origin="test")
    assert rep["verdict"] == "GENUINE"

    # edit line 3, delete line 6, insert a fake line
    cur = list(lines)
    cur[2] = "line 2 EDITED"
    del cur[5]
    cur.insert(7, "fake line")
    rep = logs_report(witness, "srv", {"auth.log": "\n".join(cur) + "\n"}, origin="test")
    assert rep["verdict"] == "TAMPERED"
    types = {(f["type"], f["line"]) for f in rep["findings"]}
    assert ("modified", 3) in types and ("deleted", 6) in types
    assert any(f["type"] == "inserted" for f in rep["findings"])
    assert all(f["proof_verified"] for f in rep["findings"] if f["type"] in ("modified", "deleted"))

    bundle = build_bundle(witness, rep)
    res = verify_bundle(bundle, witness.chain)
    assert res["verified"] == res["total"] > 0

    # wiping the file entirely is still provable
    rep = logs_report(witness, "srv", {"auth.log": None}, origin="test")
    assert rep["verdict"] == "TAMPERED" and rep["counts"]["file_missing"] == 10


def test_forged_entry_rejected_and_reenroll_continues_chain(witness):
    r = crypto.KeyRatchet()
    witness.enroll({"agent_id": "srv", "public_key": r.public_hex, "hostname": "h"})
    entries, head = make_entries(r, ["a", "b"])
    witness.ingest("srv", entries)

    attacker = crypto.KeyRatchet()  # does not hold the ratchet key
    forged, _ = make_entries(attacker, ["evil"], start_seq=2, head=head, start_line=3)
    with pytest.raises(IngestError):
        witness.ingest("srv", forged)
    assert witness.store.one("SELECT COUNT(*) AS n FROM events WHERE type = 'INVALID_ENTRY'")["n"] == 1

    # agent loses its state and re-enrolls: chain continues from the witness head
    r2 = crypto.KeyRatchet()
    res = witness.enroll({"agent_id": "srv", "public_key": r2.public_hex, "hostname": "h", "reason": "no_local_state"})
    assert res["next_seq"] == 2 and res["head_hash"] == head and len(res["known"]["auth.log"]) == 2
    more, _ = make_entries(r2, ["c"], start_seq=2, head=head, start_line=3)
    witness.ingest("srv", more)
    witness.anchor_pending()
    assert history_report(witness, "srv")["verdict"] == "GENUINE"


def test_witness_tables_are_append_only(witness):
    r = crypto.KeyRatchet()
    witness.enroll({"agent_id": "srv", "public_key": r.public_hex, "hostname": "h"})
    entries, _ = make_entries(r, ["a"])
    witness.ingest("srv", entries)
    import sqlite3

    with pytest.raises(sqlite3.DatabaseError):
        witness.store.x("UPDATE entries SET line_hash = 'x'")
    with pytest.raises(sqlite3.DatabaseError):
        witness.store.x("DELETE FROM entries")


def test_tampered_witness_detected_against_chain(witness):
    r = crypto.KeyRatchet()
    witness.enroll({"agent_id": "srv", "public_key": r.public_hex, "hostname": "h"})
    entries, _ = make_entries(r, ["a", "b", "c"])
    witness.ingest("srv", entries)
    witness.anchor_pending()
    # root on the witness drops the trigger and rewrites history
    witness.store.x("DROP TRIGGER entries_no_update")
    witness.store.x("UPDATE entries SET line_hash = ? WHERE seq = 1", (crypto.line_hash("rewritten"),))
    rep = history_report(witness, "srv")
    assert rep["verdict"] == "TAMPERED"
