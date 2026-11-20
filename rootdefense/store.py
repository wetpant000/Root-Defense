"""Witness storage: SQLite with append-only triggers on every evidence table.

Entries, batches, epochs and events can be inserted but never updated or deleted through SQL.
(Someone with root on the witness could still drop the triggers - that is exactly why batch roots
are anchored on-chain, and the auditor re-checks every root against the contract.)
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY, hostname TEXT, first_seen REAL, last_seen REAL,
    last_seq INTEGER NOT NULL DEFAULT -1, head_hash TEXT NOT NULL, expected_pk TEXT NOT NULL,
    epoch INTEGER NOT NULL DEFAULT 1, sources TEXT, status TEXT NOT NULL DEFAULT 'online', silent_since REAL
);
CREATE TABLE IF NOT EXISTS epochs (
    agent_id TEXT, epoch INTEGER, start_seq INTEGER, public_key TEXT, enrolled_at REAL, reason TEXT,
    PRIMARY KEY (agent_id, epoch)
);
CREATE TABLE IF NOT EXISTS entries (
    agent_id TEXT, seq INTEGER, ts REAL, received_at REAL, kind TEXT, source TEXT, line_no INTEGER,
    line_hash TEXT, prev_hash TEXT, next_pk TEXT, meta TEXT, hash TEXT, sig TEXT, line_enc BLOB,
    PRIMARY KEY (agent_id, seq)
);
CREATE INDEX IF NOT EXISTS entries_source ON entries (agent_id, source, line_no);
CREATE TABLE IF NOT EXISTS batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, first_seq INTEGER, last_seq INTEGER, count INTEGER,
    root TEXT, reason INTEGER, created_at REAL, chain_mode TEXT, chain_id INTEGER, contract TEXT,
    tx_hash TEXT, block_number INTEGER, chain_index INTEGER, anchor_latency REAL
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts REAL, type TEXT, severity TEXT, title TEXT,
    detail TEXT, hash TEXT
);
CREATE TABLE IF NOT EXISTS event_anchors (
    event_id INTEGER PRIMARY KEY, root TEXT, size INTEGER, leaf_index INTEGER, tx_hash TEXT, block_number INTEGER,
    chain_index INTEGER, chain_mode TEXT, contract TEXT, anchored_at REAL
);
CREATE TABLE IF NOT EXISTS acks (event_id INTEGER PRIMARY KEY, ts REAL);
"""

APPEND_ONLY = ("entries", "batches", "epochs", "events", "event_anchors")


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.executescript(SCHEMA)
            for t in APPEND_ONLY:
                for op in ("UPDATE", "DELETE"):
                    self.db.execute(
                        f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} BEFORE {op} ON {t} "
                        f"BEGIN SELECT RAISE(ABORT, '{t} is append-only'); END"
                    )

    def q(self, sql: str, args: Iterable[Any] = ()) -> list[sqlite3.Row]:
        with self.lock:
            return self.db.execute(sql, tuple(args)).fetchall()

    def one(self, sql: str, args: Iterable[Any] = ()) -> sqlite3.Row | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: Iterable[Any] = ()) -> int:
        with self.lock:
            cur = self.db.execute(sql, tuple(args))
            return cur.lastrowid

    def tx(self):
        """Context manager for an atomic block (BEGIN/COMMIT)."""
        store = self

        class _T:
            def __enter__(self_inner):
                store.lock.acquire()
                store.db.execute("BEGIN IMMEDIATE")
                return store

            def __exit__(self_inner, exc_type, *_):
                try:
                    store.db.execute("ROLLBACK" if exc_type else "COMMIT")
                finally:
                    store.lock.release()

        return _T()


def row_dict(r: sqlite3.Row | None) -> dict | None:
    if r is None:
        return None
    d = dict(r)
    for k in ("meta", "detail", "sources"):
        if k in d and isinstance(d[k], str):
            try:
                d[k] = json.loads(d[k])
            except json.JSONDecodeError:
                pass
    d.pop("line_enc", None)
    return d
