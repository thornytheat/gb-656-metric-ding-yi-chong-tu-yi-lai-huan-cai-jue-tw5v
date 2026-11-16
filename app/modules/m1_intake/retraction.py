"""敏感原文撤回：按来源内容摘要与行号定位，留下无原文的凭据。

撤回清三处存原文的地方——隔离区、快照、批次；诊断行本身保留，
原因码、明细与采信账不动，历史页面照样解释当时为何阻断。
凭据只记原因码与原文摘要，永不回存原文。
"""

from __future__ import annotations

import re

from app import errors, store

SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _validate(source_sha256, line) -> tuple[str, int]:
    if not isinstance(source_sha256, str) or not SHA256_RE.fullmatch(source_sha256.strip().lower()):
        raise errors.BadInput(
            "source_sha256 必须是 64 位十六进制摘要",
            detail={"field": "source_sha256"},
        )
    if isinstance(line, bool) or not isinstance(line, int) or line < 0:
        raise errors.BadInput("line 必须是不小于 0 的整数", detail={"field": "line"})
    return source_sha256.strip().lower(), line


def retract(source_sha256, line) -> dict:
    """撤回一份来源某一行诊断里的原文，返回凭据与是否复用。"""
    source, lineno = _validate(source_sha256, line)
    result = store.apply_retraction(source, lineno)
    if result is None:
        raise errors.NotFound(
            "该来源与行号没有可撤回的原文",
            detail={"source_sha256": source, "line": lineno},
        )
    return {"retraction": result["credential"], "reused": result["reused"]}


def credentials(source_sha256: str | None = None) -> list[dict]:
    return store.list_retractions(source_sha256)


def enrich_rows(rows: list[dict], digests: dict) -> list[dict]:
    """给隔离行补来源摘要，页面与接口才能按内容定位撤回。"""
    return [
        dict(row, source_sha256=digests.get(row.get("side") or "", ""))
        for row in rows
    ]
