from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

from tests.conftest import EVENTS, RECEIPTS, REPO_ROOT

SECRET_RE = re.compile(r"DEMOSECRET-[A-Z0-9]+-[A-Z0-9]{16}")


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-m", "agent_trace_audit", *args],
        cwd=REPO_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=60,
    )


def test_cli_audit_writes_redacted_artifacts(tmp_path):
    result = _run(
        "audit",
        "--events",
        str(EVENTS),
        "--receipts",
        str(RECEIPTS),
        "--out",
        str(tmp_path),
    )
    assert result.returncode == 0, result.stderr
    for name in (
        "audit-report.json",
        "audit-report.html",
        "events.redacted.jsonl",
        "receipts.redacted.jsonl",
    ):
        path = tmp_path / name
        assert path.is_file()
        assert not SECRET_RE.search(path.read_text(encoding="utf-8"))
    report = json.loads((tmp_path / "audit-report.json").read_text(encoding="utf-8"))
    assert report["summary"]["provenance_chains"] == 1
    assert report["summary"]["duplicates_removed"] == 1


def test_cli_fail_on_high(tmp_path):
    result = _run(
        "audit",
        "--events",
        str(EVENTS),
        "--receipts",
        str(RECEIPTS),
        "--out",
        str(tmp_path),
        "--fail-on-high",
    )
    assert result.returncode == 1


def test_cli_collect_only(tmp_path):
    result = _run(
        "collect",
        "--events",
        str(EVENTS),
        "--receipts",
        str(RECEIPTS),
        "--out",
        str(tmp_path / "collected"),
    )
    assert result.returncode == 0, result.stderr
    events = (tmp_path / "collected" / "events.redacted.jsonl").read_text(encoding="utf-8")
    assert not SECRET_RE.search(events)
    assert len(events.splitlines()) == 7


def test_cli_missing_input_reports_issue(tmp_path):
    result = _run(
        "audit",
        "--events",
        str(tmp_path / "missing.jsonl"),
        "--out",
        str(tmp_path / "out"),
    )
    assert result.returncode == 0
    report = json.loads((tmp_path / "out" / "audit-report.json").read_text(encoding="utf-8"))
    assert any(issue["kind"] == "input_error" for issue in report["collection_issues"])
