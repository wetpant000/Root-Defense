"""Hashing, entry format, forward-secure signing and Merkle trees.

Everything that is anchored or verified goes through this module, so the agent, the witness and
an independent auditor all compute exactly the same values.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

ENTRY_DOMAIN = b"RD-ENTRY-v1\x00"
EVENT_DOMAIN = b"RD-EVENT-v1\x00"
LINE_DOMAIN = b"RD-LINE-v1\x00"
GENESIS_HASH = "0" * 64

# Fields of an entry that are covered by its hash (and therefore by its signature and Merkle root).
ENTRY_FIELDS = ("agent_id", "seq", "ts", "kind", "source", "line_no", "line_hash", "prev_hash", "next_pk", "meta")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def line_hash(line: str) -> str:
    """Hash of a single raw log line. The line text itself never goes on-chain."""
    return sha256_hex(LINE_DOMAIN + line.encode("utf-8", "surrogateescape"))


def entry_payload(entry: dict) -> dict:
    return {k: entry.get(k) for k in ENTRY_FIELDS}


def entry_hash(entry: dict) -> str:
    """Hash-chain link: covers the previous entry's hash, so changing any entry breaks every later one."""
    return sha256_hex(ENTRY_DOMAIN + canonical_json(entry_payload(entry)))


def event_hash(event: dict) -> str:
    fields = {k: event.get(k) for k in ("agent_id", "ts", "type", "severity", "title", "detail")}
    return sha256_hex(EVENT_DOMAIN + canonical_json(fields))


def stream_id(agent_id: str, kind: str = "entries") -> str:
    """bytes32 identifier of an anchored stream on the contract."""
    return "0x" + sha256_hex(f"rootdefense:{kind}:{agent_id}".encode())


# --------------------------------------------------------------------------- signatures


def pk_hex(pk: Ed25519PublicKey) -> str:
    return pk.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def verify_sig(pk_hex_str: str, msg_hex: str, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex_str)).verify(bytes.fromhex(sig_hex), bytes.fromhex(msg_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


class KeyRatchet:
    """Forward-secure signer.

    Every entry is signed with the *current* key and carries the public half of a freshly generated
    *next* key. Right after signing, the current private key is discarded and the next one takes
    over. A verifier that knows the first public key (registered with the witness at enrollment)
    can follow the chain of public keys, but an attacker who later steals the agent's key only gets
    the key for *future* entries: every earlier private key is already gone, so history cannot be
    re-signed.
    """

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._sk = private_key or Ed25519PrivateKey.generate()

    @property
    def public_hex(self) -> str:
        return pk_hex(self._sk.public_key())

    def export_private(self) -> str:
        return self._sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()

    @classmethod
    def from_private_hex(cls, h: str) -> "KeyRatchet":
        return cls(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(h)))

    def seal(self, entry: dict) -> dict:
        """Fill in next_pk, hash and sig, then ratchet forward (old private key is dropped)."""
        nxt = Ed25519PrivateKey.generate()
        entry["next_pk"] = pk_hex(nxt.public_key())
        entry["hash"] = entry_hash(entry)
        entry["sig"] = self._sk.sign(bytes.fromhex(entry["hash"])).hex()
        self._sk = nxt  # the previous key is no longer referenced anywhere
        return entry


# --------------------------------------------------------------------------- Merkle tree (RFC 6962 style)


def _leaf(h: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + h).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: Sequence[bytes]) -> bytes:
    n = len(leaves)
    if n == 1:
        return _leaf(leaves[0])
    k = _split(n)
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def merkle_root(hashes_hex: Sequence[str]) -> str:
    if not hashes_hex:
        raise ValueError("cannot build a Merkle tree of zero leaves")
    return "0x" + _mth([bytes.fromhex(h) for h in hashes_hex]).hex()


def _path(m: int, leaves: Sequence[bytes]) -> list[bytes]:
    n = len(leaves)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, leaves[:k]) + [_mth(leaves[k:])]
    return _path(m - k, leaves[k:]) + [_mth(leaves[:k])]


def merkle_proof(hashes_hex: Sequence[str], index: int) -> list[str]:
    """Inclusion proof for leaf `index` (list of sibling hashes, bottom-up)."""
    return [p.hex() for p in _path(index, [bytes.fromhex(h) for h in hashes_hex])]


def root_from_proof(leaf_hex: str, index: int, size: int, proof: Sequence[str]) -> str:
    """Recompute the root from one leaf and its inclusion proof."""
    path = [bytes.fromhex(p) for p in proof]

    def rec(m: int, n: int, p: list[bytes]) -> bytes:
        if n == 1:
            if p:
                raise ValueError("proof too long")
            return _leaf(bytes.fromhex(leaf_hex))
        if not p:
            raise ValueError("proof too short")
        k = _split(n)
        if m < k:
            return _node(rec(m, k, p[:-1]), p[-1])
        return _node(p[-1], rec(m - k, n - k, p[:-1]))

    return "0x" + rec(index, size, path).hex()


def verify_proof(leaf_hex: str, index: int, size: int, proof: Sequence[str], root: str) -> bool:
    try:
        return root_from_proof(leaf_hex, index, size, proof).lower() == root.lower()
    except ValueError:
        return False


@dataclass
class ChainCheck:
    ok: bool
    problem: str | None = None


def check_link(prev_hash: str, entry: dict, expected_seq: int, expected_pk: str) -> ChainCheck:
    """Validate one entry against the chain head: sequence, prev link, hash and signature."""
    if entry.get("seq") != expected_seq:
        return ChainCheck(False, f"sequence gap: expected {expected_seq}, got {entry.get('seq')}")
    if entry.get("prev_hash") != prev_hash:
        return ChainCheck(False, "hash chain broken (prev_hash does not match previous entry)")
    if entry_hash(entry) != entry.get("hash"):
        return ChainCheck(False, "entry content does not match its hash")
    if not verify_sig(expected_pk, entry["hash"], entry.get("sig", "")):
        return ChainCheck(False, "signature invalid for the expected ratchet key")
    return ChainCheck(True)


def iter_chunks(seq: Sequence, size: int) -> Iterable[Sequence]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]
