"""SQLite 读写：批次快照、运行清单、隔离行、撤回凭据、键值状态。

只放数据访问，不放判定；调用方拿到的是普通字典。
撤回相关的存储不变量也守在这里：凡写入隔离行、快照、批次，
先对照撤回注册表洗刷原文，保证已撤回的内容不会被重新落库。
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path

from app import config

_LOCK = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    schema_id      TEXT PRIMARY KEY,
    version_label  TEXT NOT NULL,
    source_path    TEXT NOT NULL,
    source_sha256  TEXT NOT NULL,
    encoding       TEXT NOT NULL,
    bom            INTEGER NOT NULL,
    field_count    INTEGER NOT NULL,
    blocked_count  INTEGER NOT NULL,
    created_at     TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    run_id         TEXT PRIMARY KEY,
    batch_key      TEXT NOT NULL UNIQUE,
    old_schema_id  TEXT NOT NULL,
    new_schema_id  TEXT NOT NULL,
    version_seq    INTEGER NOT NULL,
    input_sha256   TEXT NOT NULL,
    ruleset        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    effective_from TEXT NOT NULL,
    effective_to   TEXT,
    summary_json   TEXT NOT NULL,
    payload_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quarantine (
    schema_id     TEXT NOT NULL,
    line          INTEGER,
    table_name    TEXT,
    column_name   TEXT,
    reason        TEXT NOT NULL,
    blocking      INTEGER NOT NULL,
    detail        TEXT,
    raw           TEXT,
    retracted     INTEGER NOT NULL DEFAULT 0,
    retraction_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS retractions (
    retraction_id  TEXT PRIMARY KEY,
    source_sha256  TEXT NOT NULL,
    line           INTEGER NOT NULL,
    reasons_json   TEXT NOT NULL,
    raw_sha256_json TEXT NOT NULL,
    hits_json      TEXT NOT NULL,
    ruleset        TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    UNIQUE (source_sha256, line)
);
CREATE TABLE IF NOT EXISTS kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quarantine_schema ON quarantine(schema_id);
CREATE INDEX IF NOT EXISTS idx_retractions_source ON retractions(source_sha256, line);
"""

# 老库缺少的列在这里补齐，CREATE TABLE IF NOT EXISTS 不会回头改旧表
_QUARANTINE_COLUMNS = {
    "retracted": "ALTER TABLE quarantine ADD COLUMN retracted INTEGER NOT NULL DEFAULT 0",
    "retraction_id": "ALTER TABLE quarantine ADD COLUMN retraction_id TEXT NOT NULL DEFAULT ''",
}


def db_path() -> Path:
    raw = os.environ.get("METRICGRAPH_DB", "").strip()
    path = Path(raw) if raw else config.DEFAULT_DB
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db() -> None:
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)
        existing = {row["name"] for row in conn.execute("PRAGMA table_info(quarantine)")}
        for column, ddl in _QUARANTINE_COLUMNS.items():
            if column not in existing:
                conn.execute(ddl)


def reset() -> None:
    """测试与重建用：清空全部业务表。"""
    with _LOCK, _connect() as conn:
        conn.executescript(SCHEMA)
        for table in ("snapshots", "runs", "quarantine", "retractions", "kv"):
            conn.execute(f"DELETE FROM {table}")


def _dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _loads(value):
    if not value:
        return None
    return json.loads(value)


# ---------- 快照 ----------

def _upsert_snapshot(conn: sqlite3.Connection, snapshot: dict) -> None:
    conn.execute(
        """INSERT INTO snapshots (schema_id, version_label, source_path, source_sha256,
               encoding, bom, field_count, blocked_count, created_at, payload_json)
           VALUES (?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(schema_id) DO UPDATE SET
               version_label=excluded.version_label,
               source_path=excluded.source_path,
               source_sha256=excluded.source_sha256,
               encoding=excluded.encoding,
               bom=excluded.bom,
               field_count=excluded.field_count,
               blocked_count=excluded.blocked_count,
               created_at=excluded.created_at,
               payload_json=excluded.payload_json""",
        (
            snapshot["schema_id"], snapshot["version_label"], snapshot["source_path"],
            snapshot["source_sha256"], snapshot["encoding"], int(bool(snapshot["bom"])),
            int(snapshot["field_count"]), int(snapshot["blocked_count"]),
            snapshot["created_at"], _dumps(snapshot),
        ),
    )


def _replace_quarantine(conn: sqlite3.Connection, schema_id: str, rows: list[dict]) -> None:
    conn.execute("DELETE FROM quarantine WHERE schema_id=?", (schema_id,))
    conn.executemany(
        """INSERT INTO quarantine (schema_id, line, table_name, column_name, reason,
               blocking, detail, raw, retracted, retraction_id) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        [
            (
                schema_id, int(row.get("line") or 0), row.get("table") or "",
                row.get("column") or "", row["reason"], int(bool(row.get("blocking"))),
                row.get("detail") or "", row.get("raw") or "",
                int(bool(row.get("retracted"))), row.get("retraction_id") or "",
            )
            for row in rows
        ],
    )


def save_intake(snapshot: dict) -> dict:
    """一个事务落快照与隔离行，返回实际落库的快照。

    命中撤回注册表的诊断在写库前洗刷原文：撤回与采信在锁下串行，
    无论谁先谁后，已撤回的原文都不会重新出现。
    """
    with _LOCK, _connect() as conn:
        registry = _retraction_map(conn)
        stored = snapshot
        if registry:
            stored = dict(snapshot)
            stored["diagnostics"] = [dict(row) for row in snapshot.get("diagnostics") or []]
            _scrub_snapshot_payload(stored, registry)
        _upsert_snapshot(conn, stored)
        _replace_quarantine(conn, stored["schema_id"], stored["diagnostics"])
    return stored


def load_snapshot(schema_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM snapshots WHERE schema_id=?", (schema_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_snapshots(limit: int = 20) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT schema_id, version_label, source_path, source_sha256, encoding, bom,
                      field_count, blocked_count, created_at
               FROM snapshots ORDER BY created_at DESC, schema_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def list_quarantine(schema_id: str) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT line, table_name, column_name, reason, blocking, detail, raw,
                      retracted, retraction_id
               FROM quarantine WHERE schema_id=? ORDER BY line, reason""",
            (schema_id,),
        ).fetchall()
    return [
        {
            "line": row["line"],
            "table": row["table_name"],
            "column": row["column_name"],
            "reason": row["reason"],
            "blocking": bool(row["blocking"]),
            "detail": row["detail"],
            "raw": row["raw"],
            "retracted": bool(row["retracted"]),
            "retraction_id": row["retraction_id"],
        }
        for row in rows
    ]


# ---------- 运行清单 ----------

def save_run(run: dict) -> None:
    """落批次；撤回注册表非空时先深拷贝洗刷，调用方的内存对象不动。"""
    with _LOCK, _connect() as conn:
        registry = _retraction_map(conn)
        payload = run
        if registry:
            payload = copy.deepcopy(run)
            _scrub_run_payload(payload, registry)
        conn.execute(
            """INSERT INTO runs (run_id, batch_key, old_schema_id, new_schema_id, version_seq,
                   input_sha256, ruleset, created_at, effective_from, effective_to,
                   summary_json, payload_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                payload["run_id"], payload["batch_key"], payload["old_schema_id"],
                payload["new_schema_id"], int(payload["version_seq"]),
                payload["input_sha256"], payload["ruleset"], payload["created_at"],
                payload["effective_from"], payload["effective_to"],
                _dumps(payload["summary"]), _dumps(payload),
            ),
        )


def find_run_by_key(batch_key: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE batch_key=?", (batch_key,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def run_by_id(run_id: str) -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs WHERE run_id=?", (run_id,)
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def latest_run() -> dict | None:
    with _LOCK, _connect() as conn:
        row = conn.execute(
            "SELECT payload_json FROM runs ORDER BY version_seq DESC LIMIT 1"
        ).fetchone()
    return _loads(row["payload_json"]) if row else None


def list_runs(limit: int = 30) -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            """SELECT summary_json FROM runs ORDER BY version_seq DESC, run_id LIMIT ?""",
            (limit,),
        ).fetchall()
    return [_loads(row["summary_json"]) for row in rows]


def count_runs() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM runs").fetchone()
    return int(row["n"])


def next_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"]) + 1


def current_version_seq() -> int:
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT COALESCE(MAX(version_seq), 0) AS n FROM runs").fetchone()
    return int(row["n"])


def list_windows() -> list[dict]:
    with _LOCK, _connect() as conn:
        rows = conn.execute(
            "SELECT run_id, effective_from, effective_to FROM runs ORDER BY version_seq"
        ).fetchall()
    return [dict(row) for row in rows]


# ---------- 撤回凭据 ----------

def _retraction_out(row: sqlite3.Row) -> dict:
    return {
        "retraction_id": row["retraction_id"],
        "source_sha256": row["source_sha256"],
        "line": int(row["line"]),
        "reasons": _loads(row["reasons_json"]) or [],
        "raw_sha256": _loads(row["raw_sha256_json"]) or [],
        "hits": _loads(row["hits_json"]) or {},
        "ruleset": row["ruleset"],
        "created_at": row["created_at"],
    }


def _retraction_map(conn: sqlite3.Connection) -> dict:
    """(来源摘要, 行号) -> 凭据号，写入路径上的防复活注册表。"""
    rows = conn.execute(
        "SELECT source_sha256, line, retraction_id FROM retractions"
    ).fetchall()
    return {(row["source_sha256"], int(row["line"])): row["retraction_id"] for row in rows}


def _find_retraction(conn: sqlite3.Connection, source_sha256: str, line: int) -> dict | None:
    row = conn.execute(
        "SELECT * FROM retractions WHERE source_sha256=? AND line=?",
        (source_sha256, line),
    ).fetchone()
    return _retraction_out(row) if row else None


def list_retractions(source_sha256: str | None = None) -> list[dict]:
    with _LOCK, _connect() as conn:
        if source_sha256:
            rows = conn.execute(
                """SELECT * FROM retractions WHERE source_sha256=?
                   ORDER BY created_at DESC, retraction_id""",
                (source_sha256,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM retractions ORDER BY created_at DESC, retraction_id"
            ).fetchall()
    return [_retraction_out(row) for row in rows]


def _scrub_row(row: dict, retraction_id: str) -> None:
    row["raw"] = ""
    row["retracted"] = True
    row["retraction_id"] = retraction_id


def _scrub_rows_with_registry(rows, source_sha256: str, registry: dict) -> bool:
    changed = False
    for item in rows or []:
        key = (source_sha256, int(item.get("line") or 0))
        if key in registry and item.get("raw"):
            _scrub_row(item, registry[key])
            changed = True
    return changed


def _scrub_snapshot_payload(snapshot: dict, registry: dict) -> bool:
    return _scrub_rows_with_registry(
        snapshot.get("diagnostics") or [], snapshot.get("source_sha256") or "", registry
    )


def _scrub_run_payload(run: dict, registry: dict) -> bool:
    digests = run.get("digests") or {}
    changed = False
    for item in run.get("quarantine") or []:
        changed |= _scrub_rows_with_registry(
            [item], digests.get(item.get("side") or "", ""), registry
        )
    changed |= _scrub_rows_with_registry(
        run.get("quarantine_old"), digests.get("old", ""), registry
    )
    changed |= _scrub_rows_with_registry(
        run.get("quarantine_new"), digests.get("new", ""), registry
    )
    return changed


def _scrub_run_lists(run: dict, source_sha256: str, line: int, retraction_id: str) -> bool:
    """清批次载荷里同一来源同一行的原文；quarantine 三份清单按 side 对摘要。"""
    digests = run.get("digests") or {}
    changed = False

    def scrub(rows, source: str) -> None:
        nonlocal changed
        if source != source_sha256:
            return
        for item in rows or []:
            if int(item.get("line") or 0) == line and item.get("raw"):
                _scrub_row(item, retraction_id)
                changed = True

    for item in run.get("quarantine") or []:
        scrub([item], digests.get(item.get("side") or "", ""))
    scrub(run.get("quarantine_old"), digests.get("old", ""))
    scrub(run.get("quarantine_new"), digests.get("new", ""))
    return changed


def _scrub_stored_snapshots(conn: sqlite3.Connection, source_sha256: str,
                            line: int, retraction_id: str) -> int:
    """清已存快照里同一来源同一行的原文，返回改动的快照数。"""
    touched = 0
    rows = conn.execute(
        "SELECT schema_id, payload_json FROM snapshots WHERE source_sha256=?",
        (source_sha256,),
    ).fetchall()
    for row in rows:
        payload = _loads(row["payload_json"])
        changed = False
        for diag in payload.get("diagnostics") or []:
            if int(diag.get("line") or 0) == line and diag.get("raw"):
                _scrub_row(diag, retraction_id)
                changed = True
        if changed:
            touched += 1
            conn.execute(
                "UPDATE snapshots SET payload_json=? WHERE schema_id=?",
                (_dumps(payload), row["schema_id"]),
            )
    return touched


def _scrub_stored_runs(conn: sqlite3.Connection, source_sha256: str,
                       line: int, retraction_id: str) -> int:
    """清已存批次里同一来源同一行的原文，返回改动的批次数。"""
    touched = 0
    rows = conn.execute("SELECT run_id, payload_json FROM runs").fetchall()
    for row in rows:
        payload = _loads(row["payload_json"])
        if _scrub_run_lists(payload, source_sha256, line, retraction_id):
            touched += 1
            conn.execute(
                "UPDATE runs SET payload_json=? WHERE run_id=?",
                (_dumps(payload), row["run_id"]),
            )
    return touched


def apply_retraction(source_sha256: str, line: int) -> dict | None:
    """按来源摘要与行号清场：隔离区、快照、批次一个事务，失败整体回滚。

    返回 {"credential": ..., "reused": bool}；该来源与行号没有可撤回的
    原文时返回 None。凭据号由定位键推导，重撤同一目标命中已有凭据，
    不会新增记录。
    """
    retraction_id = "ret-" + hashlib.sha256(
        f"{source_sha256}|{line}".encode("utf-8")
    ).hexdigest()[:12]
    with _LOCK, _connect() as conn:
        existing = _find_retraction(conn, source_sha256, line)
        if existing is not None:
            return {"credential": existing, "reused": True}
        targets = conn.execute(
            """SELECT q.rowid AS rid, q.reason AS reason, q.raw AS raw
               FROM quarantine q JOIN snapshots s ON s.schema_id = q.schema_id
               WHERE s.source_sha256=? AND q.line=? AND q.raw <> ''""",
            (source_sha256, line),
        ).fetchall()
        if not targets:
            return None
        credential = {
            "retraction_id": retraction_id,
            "source_sha256": source_sha256,
            "line": line,
            "reasons": sorted({row["reason"] for row in targets}),
            "raw_sha256": sorted(
                {hashlib.sha256((row["raw"] or "").encode("utf-8")).hexdigest()
                 for row in targets}
            ),
            "hits": {
                "quarantine": len(targets),
                "snapshots": _scrub_stored_snapshots(conn, source_sha256, line,
                                                     retraction_id),
                "runs": _scrub_stored_runs(conn, source_sha256, line, retraction_id),
            },
            "ruleset": config.RULESET_VERSION,
            "created_at": config.now_utc().isoformat(),
        }
        conn.execute(
            "UPDATE quarantine SET raw='', retracted=1, retraction_id=?"
            f" WHERE rowid IN ({','.join('?' * len(targets))})",
            [retraction_id, *[row["rid"] for row in targets]],
        )
        conn.execute(
            """INSERT INTO retractions (retraction_id, source_sha256, line, reasons_json,
                   raw_sha256_json, hits_json, ruleset, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                retraction_id, source_sha256, line, _dumps(credential["reasons"]),
                _dumps(credential["raw_sha256"]), _dumps(credential["hits"]),
                credential["ruleset"], credential["created_at"],
            ),
        )
    return {"credential": credential, "reused": False}


# ---------- 键值 ----------

def set_kv(key: str, value) -> None:
    with _LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO kv (k, v) VALUES (?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            (key, _dumps(value)),
        )


def get_kv(key: str, default=None):
    with _LOCK, _connect() as conn:
        row = conn.execute("SELECT v FROM kv WHERE k=?", (key,)).fetchone()
    return _loads(row["v"]) if row else default
