"""Auditor engine.

Two independent checks:

1. History check - recomputes every hash link, ratchet signature, line hash and Merkle root held by the
   witness and compares each root with the value stored on-chain. Detects tampering with the witness.
2. Log check - compares the log files as they exist *now* on the server (live snapshot or upload)
   against the witnessed history, and pinpoints modified, deleted and inserted lines, each backed by a
   Merkle inclusion proof against the on-chain root.
"""
from __future__ import annotations

import json
import secrets
import time
from bisect import bisect_right
from difflib import SequenceMatcher

from .core import crypto

AUTHENTIC_TYPES = ("modified", "deleted", "inserted", "file_missing")


def _entry_dict(r) -> dict:
    d = dict(r)
    d["meta"] = json.loads(d["meta"]) if d.get("meta") else {}
    return d


class _History:
    """Loads and verifies everything the witness holds for one agent."""

    def __init__(self, w, agent_id: str):
        self.w = w
        self.agent_id = agent_id
        # Read batches before entries: a batch only ever references entries that already exist,
        # so this order gives a consistent view while the witness keeps ingesting and anchoring.
        self.batches = [dict(r) for r in w.store.q("SELECT * FROM batches WHERE agent_id = ? ORDER BY first_seq", (agent_id,))]
        self.epochs = {r["start_seq"]: r for r in w.store.q("SELECT * FROM epochs WHERE agent_id = ? ORDER BY epoch", (agent_id,))}
        self.entries = [_entry_dict(r) for r in w.store.q("SELECT * FROM entries WHERE agent_id = ? ORDER BY seq", (agent_id,))]
        self.by_seq = {e["seq"]: e for e in self.entries}
        self._batch_starts = [b["first_seq"] for b in self.batches]
        self.issues: list[dict] = []
        self.sig_ok = self.links_ok = 0
        self._verify_entries()

    def verify_against_chain(self, chain_anchors: dict[int, dict], chain_error: str | None) -> None:
        self._verify_batches(chain_anchors, chain_error)

    def _verify_entries(self) -> None:
        head, pk, expected = crypto.GENESIS_HASH, None, 0
        for e in self.entries:
            if e["seq"] in self.epochs:
                pk = self.epochs[e["seq"]]["public_key"]
            chk = crypto.check_link(head, e, expected, pk or "")
            if chk.ok:
                self.links_ok += 1
                self.sig_ok += 1
            else:
                self.issues.append({"seq": e["seq"], "where": "witness", "problem": chk.problem})
            if e["kind"] == "log" and e.get("line_enc") is not None:
                try:
                    text = self.w.decrypt(e["line_enc"])
                    if crypto.line_hash(text) != e["line_hash"]:
                        self.issues.append({"seq": e["seq"], "where": "witness", "problem": "stored log text does not match its hash"})
                    e["line"] = text
                except Exception:  # noqa: BLE001
                    self.issues.append({"seq": e["seq"], "where": "witness", "problem": "stored log text cannot be decrypted"})
            head, expected, pk = e["hash"], e["seq"] + 1, e["next_pk"]

    def _verify_batches(self, anchors: dict[int, dict], chain_error: str | None) -> None:
        sid = crypto.stream_id(self.agent_id)
        for b in self.batches:
            hashes = [self.by_seq[s]["hash"] for s in range(b["first_seq"], b["last_seq"] + 1) if s in self.by_seq]
            local_root = crypto.merkle_root(hashes) if len(hashes) == b["count"] else None
            on = anchors.get(b["chain_index"])
            if local_root != b["root"]:
                b["status"], b["status_text"] = "mismatch", "Witness entries no longer match the anchored root"
            elif on is None:
                b["status"], b["status_text"] = "unavailable", chain_error or "On-chain record not found"
            elif (on["root"].lower(), on["streamId"].lower(), on["firstSeq"], on["lastSeq"], on["count"]) != (
                    b["root"].lower(), sid.lower(), b["first_seq"], b["last_seq"], b["count"]):
                b["status"], b["status_text"] = "mismatch", "On-chain record differs from the witness batch"
            else:
                b["status"], b["status_text"] = "verified", "Root matches the on-chain record"
                b["chain_timestamp"] = on["timestamp"]
            b["explorer"] = self.w.chain.explorer_tx(b["tx_hash"])
            if b["status"] == "mismatch":
                self.issues.append({"batch": b["id"], "where": "blockchain", "problem": b["status_text"]})

    @property
    def anchored_through(self) -> int:
        return self.batches[-1]["last_seq"] if self.batches else -1

    def batch_for(self, seq: int) -> dict | None:
        i = bisect_right(self._batch_starts, seq) - 1
        if i >= 0 and self.batches[i]["first_seq"] <= seq <= self.batches[i]["last_seq"]:
            return self.batches[i]
        return None

    def proof_for(self, seq: int) -> dict | None:
        b = self.batch_for(seq)
        if not b:
            return None
        hashes = [self.by_seq[s]["hash"] for s in range(b["first_seq"], b["last_seq"] + 1)]
        idx = seq - b["first_seq"]
        proof = crypto.merkle_proof(hashes, idx)
        return {"batch_id": b["id"], "root": b["root"], "leaf": hashes[idx], "index": idx, "size": len(hashes), "proof": proof,
                "chain_index": b["chain_index"], "tx_hash": b["tx_hash"], "block_number": b["block_number"],
                "explorer": b.get("explorer"),
                "verified": b["status"] == "verified" and crypto.verify_proof(hashes[idx], idx, len(hashes), proof, b["root"])}

    def summary(self) -> dict:
        verified = sum(1 for b in self.batches if b["status"] == "verified")
        return {"agent_id": self.agent_id, "entries_checked": len(self.entries), "links_ok": self.links_ok,
                "signatures_ok": self.sig_ok, "epochs": len(self.epochs), "batches_total": len(self.batches),
                "batches_verified": verified, "pending_entries": len(self.entries) - 1 - self.anchored_through if self.entries else 0,
                "issues": self.issues}


def _load(w, agent_ids: list[str]) -> tuple[dict[str, _History], str | None]:
    hists = {a: _History(w, a) for a in agent_ids}
    idx = sorted({b["chain_index"] for h in hists.values() for b in h.batches if b["chain_index"] is not None})
    anchors, err = {}, None
    try:
        anchors = w.chain.get_anchors(idx)
    except Exception as e:  # noqa: BLE001
        err = f"Blockchain unavailable: {e}"
    for h in hists.values():
        h.verify_against_chain(anchors, err)
    return hists, err


def _verify_events(w) -> dict:
    rows = w.store.q("SELECT e.*, x.root, x.size, x.leaf_index, x.chain_index, x.tx_hash FROM events e "
                     "JOIN event_anchors x ON x.event_id = e.id ORDER BY e.id")
    groups: dict[int, list] = {}
    for r in rows:
        groups.setdefault(r["chain_index"], []).append(r)
    ok = bad = 0
    try:
        anchors = w.chain.get_anchors(list(groups))
    except Exception:  # noqa: BLE001
        anchors = {}
    for ci, rs in groups.items():
        hashes = []
        for r in rs:
            ev = {"agent_id": r["agent_id"], "ts": r["ts"], "type": r["type"], "severity": r["severity"], "title": r["title"],
                  "detail": json.loads(r["detail"])}
            hashes.append(crypto.event_hash(ev))
        on = anchors.get(ci)
        if on and crypto.merkle_root(hashes).lower() == on["root"].lower():
            ok += len(rs)
        else:
            bad += len(rs)
    return {"events_verified": ok, "events_failed": bad}


def history_report(w, agent_id: str | None = None) -> dict:
    ids = [agent_id] if agent_id else [r["agent_id"] for r in w.store.q("SELECT agent_id FROM agents ORDER BY agent_id")]
    hists, err = _load(w, ids)
    summaries = [h.summary() for h in hists.values()]
    issues = [i | {"agent_id": s["agent_id"]} for s in summaries for i in s["issues"]]
    unavailable = any(b["status"] == "unavailable" for h in hists.values() for b in h.batches)
    verdict = "TAMPERED" if issues else ("UNVERIFIED" if unavailable or err else "GENUINE")
    report = {
        "id": secrets.token_hex(6), "kind": "history", "created_at": time.time(), "agent_id": agent_id, "verdict": verdict,
        "headline": {
            "GENUINE": "Every witnessed entry, signature and Merkle root matches the blockchain.",
            "TAMPERED": "The witness record no longer matches what was anchored on-chain.",
            "UNVERIFIED": "The witness record is consistent, but the blockchain could not be reached to confirm it.",
        }[verdict],
        "agents": summaries, "issues": issues, "chain_error": err, "events": _verify_events(w),
        "batches": [_public_batch(b) for h in hists.values() for b in h.batches][-200:],
        "chain": _chain_meta(w),
    }
    return w.save_report(report)


def _public_batch(b: dict) -> dict:
    return {k: b.get(k) for k in ("id", "agent_id", "first_seq", "last_seq", "count", "root", "reason", "created_at",
                                  "tx_hash", "block_number", "chain_index", "status", "status_text", "explorer")}


def _chain_meta(w) -> dict:
    info = w.chain_info or {}
    return {"mode": w.chain.mode, "label": w.chain.label, "chain_id": info.get("chain_id"), "contract": w.chain.contract_address,
            "rpc": info.get("rpc"), "explorer_contract": w.chain.explorer_address(w.chain.contract_address)}


def pair_by_similarity(a: list[str], b: list[str], threshold: float = 0.5) -> list[tuple[int | None, int | None]]:
    """Order-preserving alignment of a changed block: pairs each edited line with its most similar
    counterpart, leaving unpaired lines as deletions (a) or insertions (b)."""
    n, m = len(a), len(b)
    if n == m or n * m > 2500:
        k = min(n, m)
        return [(i, i) for i in range(k)] + [(i, None) for i in range(k, n)] + [(None, j) for j in range(k, m)]
    sim = [[SequenceMatcher(None, a[i], b[j], autojunk=False).ratio() for j in range(m)] for i in range(n)]
    best = [[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(n - 1, -1, -1):
        for j in range(m - 1, -1, -1):
            take = sim[i][j] + best[i + 1][j + 1] if sim[i][j] >= threshold else -1.0
            best[i][j] = max(take, best[i + 1][j], best[i][j + 1])
    out, i, j = [], 0, 0
    while i < n and j < m:
        if sim[i][j] >= threshold and best[i][j] == sim[i][j] + best[i + 1][j + 1]:
            out.append((i, j))
            i, j = i + 1, j + 1
        elif best[i][j] == best[i + 1][j]:
            out.append((i, None))
            i += 1
        else:
            out.append((None, j))
            j += 1
    out += [(k, None) for k in range(i, n)] + [(None, k) for k in range(j, m)]
    return out


def _split_lines(text: str) -> list[str]:
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [ln.rstrip("\r") for ln in lines]


def logs_report(w, agent_id: str, files: dict[str, str | None], origin: str) -> dict:
    hists, err = _load(w, [agent_id])
    h = hists[agent_id]
    findings: list[dict] = []
    sources: list[dict] = []
    for name, text in files.items():
        auth = [e for e in h.entries if e["kind"] == "log" and e["source"] == name]
        auth.sort(key=lambda e: e["line_no"])
        if text is None:
            for e in auth:
                findings.append(_finding(h, name, "file_missing", e, None, None))
            sources.append({"source": name, "authentic_lines": len(auth), "current_lines": 0, "matching": 0, "missing": True})
            continue
        cur = _split_lines(text)
        a_hash = [e["line_hash"] for e in auth]
        c_hash = [crypto.line_hash(t) for t in cur]
        matching = 0
        for tag, i1, i2, j1, j2 in SequenceMatcher(None, a_hash, c_hash, autojunk=False).get_opcodes():
            if tag == "equal":
                matching += i2 - i1
            elif tag == "replace":
                for ai, bj in pair_by_similarity([auth[k]["line"] or "" for k in range(i1, i2)], cur[j1:j2]):
                    if ai is not None and bj is not None:
                        findings.append(_finding(h, name, "modified", auth[i1 + ai], cur[j1 + bj], j1 + bj + 1))
                    elif ai is not None:
                        findings.append(_finding(h, name, "deleted", auth[i1 + ai], None, None))
                    else:
                        findings.append(_finding(h, name, "inserted", None, cur[j1 + bj], j1 + bj + 1, before=auth[i1]["line_no"]))
            elif tag == "delete":
                for k in range(i1, i2):
                    findings.append(_finding(h, name, "deleted", auth[k], None, None))
            elif tag == "insert":
                kind = "unrecorded" if i1 == len(auth) else "inserted"
                for k in range(j1, j2):
                    findings.append(_finding(h, name, kind, None, cur[k], k + 1, before=(auth[i1]["line_no"] if i1 < len(auth) else None)))
        sources.append({"source": name, "authentic_lines": len(auth), "current_lines": len(cur), "matching": matching, "missing": False})

    counts = {t: sum(1 for f in findings if f["type"] == t) for t in (*AUTHENTIC_TYPES, "unrecorded")}
    hs = h.summary()
    tampered = any(counts[t] for t in AUTHENTIC_TYPES) or bool(hs["issues"])
    unavailable = any(b["status"] == "unavailable" for b in h.batches) or err
    verdict = "TAMPERED" if tampered else ("UNVERIFIED" if unavailable or counts["unrecorded"] else "GENUINE")
    total_bad = sum(counts[t] for t in AUTHENTIC_TYPES)
    headline = {
        "TAMPERED": f"{total_bad} line(s) on the server no longer match the witnessed, blockchain-anchored record."
                    if total_bad else "The witness record no longer matches the blockchain.",
        "UNVERIFIED": "No changes found, but some lines are not yet witnessed or the chain could not be reached.",
        "GENUINE": "Every line on the server matches the witnessed record and its on-chain Merkle root.",
    }[verdict]
    detection = None
    ev = w.store.one("SELECT detail FROM events WHERE agent_id = ? AND type = 'TAMPER_DETECTED' ORDER BY id DESC LIMIT 1", (agent_id,))
    if ev:
        detection = json.loads(ev["detail"])
    report = {
        "id": secrets.token_hex(6), "kind": "logs", "created_at": time.time(), "agent_id": agent_id, "origin": origin,
        "verdict": verdict, "headline": headline, "counts": counts, "sources": sources,
        "findings": findings[:500], "history": hs, "chain_error": err, "chain": _chain_meta(w), "last_detection": detection,
        "batches": [_public_batch(b) for b in h.batches][-50:],
    }
    return w.save_report(report)


def _finding(h: _History, source: str, ftype: str, e: dict | None, current: str | None, current_line: int | None,
             before: int | None = None) -> dict:
    f = {"source": source, "type": ftype, "line": e["line_no"] if e else None, "current_line": current_line,
         "original": e.get("line") if e else None, "current": current, "before_line": before}
    if e:
        f["seq"] = e["seq"]
        f["recorded_at"] = e["ts"]
        f["entry"] = {k: e.get(k) for k in crypto.ENTRY_FIELDS} | {"hash": e["hash"], "sig": e["sig"]}
        p = h.proof_for(e["seq"])
        f["proof"] = p
        f["anchored"] = bool(p)
        f["proof_verified"] = bool(p and p["verified"])
    return f


def build_bundle(w, report: dict) -> dict:
    """Self-contained evidence package an auditor or court can verify independently (./rd verify-bundle)."""
    return {
        "format": "root-defense-proof-bundle/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "report_id": report["id"], "verdict": report["verdict"], "headline": report["headline"],
        "agent_id": report.get("agent_id"), "origin": report.get("origin"),
        "chain": report["chain"] | {"stream_id": crypto.stream_id(report["agent_id"]) if report.get("agent_id") else None},
        "method": {
            "entry_hash": "sha256('RD-ENTRY-v1\\0' || canonical_json(entry fields))",
            "line_hash": "sha256('RD-LINE-v1\\0' || line)",
            "merkle": "RFC 6962: leaf = sha256(0x00 || entry_hash), node = sha256(0x01 || left || right)",
            "signature": "Ed25519 over entry_hash with a forward-secure key ratchet (next_pk chained in each entry)",
        },
        "counts": report.get("counts"),
        "findings": report.get("findings", []),
        "batches": report.get("batches", []),
        "history": report.get("history") or report.get("agents"),
    }


def verify_bundle(bundle: dict, chain) -> dict:
    """Independent re-verification of a proof bundle against the blockchain."""
    results = []
    proofs = [f for f in bundle.get("findings", []) if f.get("proof")]
    idx = sorted({f["proof"]["chain_index"] for f in proofs})
    anchors = chain.get_anchors(idx) if idx else {}
    for f in proofs:
        p, e = f["proof"], f["entry"]
        checks = {
            "entry_hash": crypto.entry_hash(e) == e["hash"] == p["leaf"],
            "original_line_hash": f.get("original") is None or crypto.line_hash(f["original"]) == e["line_hash"],
            "merkle_proof": crypto.verify_proof(p["leaf"], p["index"], p["size"], p["proof"], p["root"]),
            "on_chain_root": anchors.get(p["chain_index"], {}).get("root", "").lower() == p["root"].lower(),
            "current_differs": f["type"] in ("deleted", "file_missing") or (
                f.get("current") is not None and crypto.line_hash(f["current"]) != e["line_hash"]),
        }
        results.append({"source": f["source"], "line": f["line"], "type": f["type"], "checks": checks, "ok": all(checks.values())})
    return {"verified": sum(r["ok"] for r in results), "total": len(results), "results": results}
