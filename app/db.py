"""SQLite 持久化层。

三张表:
- issuers      签发者公钥簿(公钥即身份);trusted_root=1 的签发者可以签根证明。
- attestations 有向证明记录:每个 (artifact_digest, issuer) 唯一;
                parent_digest 为 NULL 表示根证明。
- revocations  撤销表:制品 digest 一旦出现,该制品及其所有后代均视为已撤销。

进程内用一把写锁串行化所有写事务,避免 SQLite 写竞争。
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from typing import Iterator

_SCHEMA = """
CREATE TABLE IF NOT EXISTS issuers (
    id           TEXT PRIMARY KEY,
    public_key   TEXT NOT NULL,
    trusted_root INTEGER NOT NULL DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS attestations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    artifact_digest TEXT NOT NULL,
    issuer          TEXT NOT NULL,
    parent_digest   TEXT,
    signature       TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_attest_unique
    ON attestations(artifact_digest, issuer);
CREATE INDEX IF NOT EXISTS idx_attest_artifact
    ON attestations(artifact_digest);
CREATE INDEX IF NOT EXISTS idx_attest_parent
    ON attestations(parent_digest);

CREATE TABLE IF NOT EXISTS revocations (
    artifact_digest TEXT PRIMARY KEY,
    reason          TEXT,
    revoked_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""

_write_lock = threading.Lock()


def db_path() -> str:
    return os.environ.get("DATABASE_PATH", "/data/supplychain.db")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    with connect() as conn:
        conn.executescript(_SCHEMA)


@contextmanager
def write_tx() -> Iterator[sqlite3.Connection]:
    """持有进程写锁的读写事务;连接随事务一起关闭。"""
    with _write_lock, connect() as conn:
        yield conn


def query_all(sql: str, params: tuple = ()) -> list[sqlite3.Row]:
    with connect() as conn:
        return conn.execute(sql, params).fetchall()


def query_one(sql: str, params: tuple = ()) -> sqlite3.Row | None:
    with connect() as conn:
        return conn.execute(sql, params).fetchone()
