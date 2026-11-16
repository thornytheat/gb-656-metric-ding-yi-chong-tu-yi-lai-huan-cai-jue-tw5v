"""敏感原文撤回：定位、凭据、幂等、回滚、并发不复活、修订不误删、导出边界。"""

from __future__ import annotations

import copy
import threading

import pytest

from app import config, store
from app.modules.m1_intake import retraction
from app.modules.m1_intake import service as intake

SECRET_TOKEN = "fid=1005"  # schema_v2026_06.sql 第 7 行坏行里的敏感原文片段


def _old_sha() -> str:
    return store.latest_run()["digests"]["old"]


def _old_schema_id() -> str:
    return store.latest_run()["old_schema_id"]


def _malformed(rows: list[dict]) -> dict:
    return next(row for row in rows if row["line"] == 7 and row["reason"] == "LINE_MALFORMED")


def _retract(client, sha: str, line: int = 7):
    return client.post("/api/schemas/retract", json={"source_sha256": sha, "line": line})


def test_retract_scrubs_snapshot_run_and_quarantine(client):
    """撤回后三处存储都不再保留原文，但诊断行与采信账原样保留。"""
    sha = _old_sha()
    schema_id = _old_schema_id()
    run_id = store.latest_run()["run_id"]

    before = store.list_quarantine(schema_id)
    assert SECRET_TOKEN in _malformed(before)["raw"]
    stats_before = store.load_snapshot(schema_id)["stats"]

    response = _retract(client, sha)
    assert response.status_code == 200
    body = response.json()
    assert body["reused"] is False
    credential = body["retraction"]
    assert credential["retraction_id"].startswith("ret-")
    assert credential["reasons"] == ["LINE_MALFORMED"]
    assert credential["raw_sha256"], "凭据要留原文摘要作证据"
    assert credential["hits"] == {"quarantine": 1, "snapshots": 1, "runs": 1}
    assert SECRET_TOKEN not in response.text, "凭据响应不得带回原文"

    # 隔离区：行还在，原文没了
    rows = store.list_quarantine(schema_id)
    assert len(rows) == len(before)
    scrubbed = _malformed(rows)
    assert scrubbed["raw"] == ""
    assert scrubbed["retracted"] is True
    assert scrubbed["retraction_id"] == credential["retraction_id"]
    assert scrubbed["reason"] == "LINE_MALFORMED"  # 当时为何阻断仍可查

    # 快照：诊断与采信账不动，只有原文被清
    snapshot = store.load_snapshot(schema_id)
    diag = _malformed(snapshot["diagnostics"])
    assert diag["raw"] == "" and diag["retracted"] is True
    assert snapshot["stats"] == stats_before
    assert snapshot["stats"]["accepted"] + snapshot["stats"]["blocked"] \
        == snapshot["stats"]["column_lines"]
    assert snapshot["blocked_count"] == snapshot["stats"]["blocked"]

    # 批次：合并清单与旧侧清单都清干净
    run = store.run_by_id(run_id)
    for key in ("quarantine", "quarantine_old"):
        row = _malformed(run[key])
        assert row["raw"] == "" and row["retracted"] is True
    assert SECRET_TOKEN not in str(run["quarantine"])


def test_retract_retry_adds_no_new_credential(client):
    sha = _old_sha()
    first = _retract(client, sha).json()
    second = _retract(client, sha).json()
    assert second["reused"] is True
    assert second["retraction"]["retraction_id"] == first["retraction"]["retraction_id"]
    assert len(store.list_retractions()) == 1


def test_retract_unknown_target_is_404(client):
    response = _retract(client, _old_sha(), line=999)
    assert response.status_code == 404
    assert response.json()["error"] == "NOT_FOUND"
    assert store.list_retractions() == []


def test_retract_validates_input(client):
    sha = _old_sha()
    assert _retract(client, "not-a-sha").status_code == 400
    assert _retract(client, sha.upper()).status_code == 200  # 大小写不敏感
    assert client.post("/api/schemas/retract",
                       json={"source_sha256": sha, "line": -1}).status_code == 400
    assert client.post("/api/schemas/retract",
                       json={"source_sha256": sha, "line": "7"}).status_code == 400
    assert client.post("/api/schemas/retract",
                       json={"source_sha256": sha, "line": True}).status_code == 400


def test_reingest_after_retract_does_not_resurrect(client):
    """撤回后再采信同一旧内容，原文不复活。"""
    sha = _old_sha()
    assert _retract(client, sha).status_code == 200

    snapshot = intake.ingest("schema_v2026_06.sql")
    row = _malformed(snapshot["diagnostics"])
    assert row["raw"] == "" and row["retracted"] is True

    stored = _malformed(store.list_quarantine(snapshot["schema_id"]))
    assert stored["raw"] == "" and stored["retracted"] is True
    persisted = _malformed(store.load_snapshot(snapshot["schema_id"])["diagnostics"])
    assert persisted["raw"] == ""


def test_concurrent_ingest_and_retract_never_resurrects(client):
    """采信与撤回并发交错，最终任何存储里都没有原文。"""
    sha = _old_sha()
    schema_id = _old_schema_id()
    failures = []

    def work(fn):
        try:
            fn()
        except Exception as exc:  # pragma: no cover - 失败即断言
            failures.append(exc)

    for _ in range(6):
        threads = [
            threading.Thread(target=work, args=(lambda: intake.ingest("schema_v2026_06.sql"),)),
            threading.Thread(target=work, args=(lambda: retraction.retract(sha, 7),)),
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert not failures
    assert _malformed(store.list_quarantine(schema_id))["raw"] == ""
    assert _malformed(store.load_snapshot(schema_id)["diagnostics"])["raw"] == ""
    assert len(store.list_retractions()) == 1


def test_save_run_is_backstop_against_resurrection(client):
    """并发窗口里带着原文的旧批次载荷，落库那一刻也要被洗刷。"""
    sha = _old_sha()
    assert _retract(client, sha).status_code == 200

    run = copy.deepcopy(store.latest_run())
    for row in run["quarantine_old"]:
        if row["line"] == 7:
            row["raw"] = f"`order_amt`  DECIMAL(18,2) NOT NULL, , -- {SECRET_TOKEN}"
            row.pop("retracted", None)
            row.pop("retraction_id", None)
    run["batch_key"] = run["batch_key"] + "-replay"
    run["run_id"] = "fm-replay"
    run["version_seq"] = 99
    store.save_run(run)

    stored = _malformed(store.run_by_id("fm-replay")["quarantine_old"])
    assert stored["raw"] == "" and stored["retracted"] is True


def test_revised_source_same_line_is_not_scrubbed(client, tmp_path, monkeypatch):
    """来源修订后同一行号命不中旧凭据，新原文不能被误删。"""
    sha = _old_sha()
    assert _retract(client, sha).status_code == 200

    revised = (
        "-- metricgraph 元数据导出 v2026_06（修订版）\n"
        "CREATE TABLE dim_order (\n"
        "  `order_id`   BIGINT        NOT NULL,  -- fid=1001\n"
        "  `order_no`   VARCHAR(64)   NOT NULL,  -- fid=1002\n"
        "  `ORDER_NO`   VARCHAR(32)   NULL,      -- fid=1003\n"
        "  `order_amt`  DECIMAL(18,2) NOT NULL,  -- fid=1004\n"
        "  `secret_amt` DECIMAL(18,2) NOT NULL, , -- fid=9001\n"
        "  `status`     VARCHAR(16)   NOT NULL,\n"
        "  `ext_json`   VARIANT       NULL,      -- fid=1007\n"
        "  `extra_col`  BIGINT        NULL       -- fid=1008\n"
        ");\n"
    )
    (tmp_path / "schema_v2026_06b.sql").write_text(revised, encoding="utf-8")
    monkeypatch.setattr(config, "SAMPLE_DIR", tmp_path)

    snapshot = intake.ingest("schema_v2026_06b.sql")
    assert snapshot["source_sha256"] != sha
    row = _malformed(snapshot["diagnostics"])
    assert "secret_amt" in row["raw"], "修订后来源相同行号不得误删"
    assert not row.get("retracted")
    stored = _malformed(store.list_quarantine(snapshot["schema_id"]))
    assert "secret_amt" in stored["raw"]
    assert len(store.list_retractions()) == 1

    # 旧来源的撤回状态不受新采信影响
    assert _malformed(store.list_quarantine(_old_schema_id()))["raw"] == ""


def test_failed_retract_rolls_back_everything(client, monkeypatch):
    """清场中途失败：隔离区、快照、凭据全部回滚，重试照常成功。"""
    sha = _old_sha()
    schema_id = _old_schema_id()
    before = store.list_quarantine(schema_id)

    original = store._scrub_stored_runs

    def boom(conn, source_sha256, line, retraction_id):
        raise RuntimeError("模拟批次清场失败")

    monkeypatch.setattr(store, "_scrub_stored_runs", boom)
    with pytest.raises(RuntimeError):
        store.apply_retraction(sha, 7)

    assert store.list_quarantine(schema_id) == before
    assert store.list_retractions() == []
    snapshot = store.load_snapshot(schema_id)
    assert SECRET_TOKEN in _malformed(snapshot["diagnostics"])["raw"]

    monkeypatch.setattr(store, "_scrub_stored_runs", original)
    result = store.apply_retraction(sha, 7)
    assert result is not None and result["reused"] is False
    assert _malformed(store.list_quarantine(schema_id))["raw"] == ""


def test_quarantine_export_respects_retraction_boundary(client):
    """隔离区 JSON 与 CSV 导出遵守同一边界：无原文，只有凭据标记。"""
    sha = _old_sha()
    assert _retract(client, sha).status_code == 200

    payload = client.get("/api/schemas/quarantine").json()
    row = _malformed(payload["rows"])
    assert row["raw"] == "" and row["retracted"] is True
    assert row["retraction_id"].startswith("ret-")
    assert SECRET_TOKEN not in str(payload)

    csv_text = client.get("/api/schemas/quarantine.csv").text
    assert SECRET_TOKEN not in csv_text
    header = csv_text.splitlines()[0].split(",")
    assert header[-2:] == ["retracted", "retraction_id"]
    line = next(item for item in csv_text.splitlines()[1:] if item.startswith("7,"))
    assert line.endswith(",Y," + row["retraction_id"])


def test_credentials_api_lists_without_raw(client):
    sha = _old_sha()
    _retract(client, sha)

    body = client.get("/api/schemas/retractions").json()
    assert body["total"] == 1
    credential = body["rows"][0]
    assert credential["line"] == 7
    assert credential["source_sha256"] == sha
    assert credential["reasons"] == ["LINE_MALFORMED"]
    assert SECRET_TOKEN not in str(body)

    filtered = client.get("/api/schemas/retractions",
                          params={"source_sha256": sha}).json()
    assert filtered["total"] == 1
    empty = client.get("/api/schemas/retractions",
                       params={"source_sha256": "0" * 64}).json()
    assert empty["total"] == 0


def test_index_page_retracts_and_shows_credentials(client):
    """采信页面：撤回按钮在行上，凭据在撤回区，撤回后页面仍解释阻断原因。"""
    home = client.get("/")
    assert 'data-action="retract"' in home.text
    assert "撤回凭据" in home.text

    sha = _old_sha()
    assert _retract(client, sha).status_code == 200

    home = client.get("/")
    assert "敏感原文已撤回" in home.text
    assert "ret-" in home.text
    assert "列定义不完整" in home.text  # 历史诊断仍解释当时为何阻断
    assert SECRET_TOKEN not in home.text
