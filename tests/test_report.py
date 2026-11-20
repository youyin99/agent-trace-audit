from __future__ import annotations

import json
import re

from agent_trace_audit.report import render_html

SECRET_RE = re.compile(r"DEMOSECRET-[A-Z0-9]+-[A-Z0-9]{16}")


def test_report_has_no_secret_plaintext(audit_report):
    serialized = json.dumps(audit_report, ensure_ascii=False)
    html = render_html(audit_report)
    assert not SECRET_RE.search(serialized)
    assert not SECRET_RE.search(html)
    assert "not a proof of causation" in html.lower()


def test_report_summary_counts(audit_report):
    summary = audit_report["summary"]
    assert summary["input_event_lines"] == 8
    assert summary["events"] == 7
    assert summary["receipts"] == 1
    assert summary["duplicates_removed"] == 1
    assert summary["provenance_chains"] == 1
    assert summary["alerts"]["high"] >= 3


def test_timeline_is_sorted(audit_report):
    timestamps = [event["timestamp"] for event in audit_report["timeline"]]
    assert timestamps == sorted(timestamps)


def test_html_escapes_untrusted_fields(audit_report):
    report = json.loads(json.dumps(audit_report))
    report["provenance"][0]["source_document"]["document_id"] = "<script>alert(1)</script>"
    report["alerts"][0]["message"] = "<img src=x onerror=alert(1)>"
    rendered = render_html(report)
    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "<img src=x" not in rendered
