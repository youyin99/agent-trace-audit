from __future__ import annotations

import json

from agent_trace_audit.collector import collect_events, collect_receipts, merge_collection
from agent_trace_audit.redaction import Redactor
from tests.conftest import RECEIPTS


def test_sample_collection_deduplicates_and_sorts(collection):
    assert collection.stats["input_events"] == 8
    assert len(collection.events) == 7
    assert collection.stats["duplicates_removed"] == 1
    assert collection.stats["out_of_order_events"] == 2
    assert collection.events[0]["event_id"] == "evt-early"
    assert [event["event_id"] for event in collection.events] == [
        "evt-early",
        "evt-read-1",
        "evt-send-1",
        "evt-deny-1",
        "evt-missing-perm",
        "evt-missing-parent",
        "evt-raw-secret",
    ]


def test_sample_collection_reports_parent_and_permission_issues(collection):
    kinds = {issue["kind"] for issue in collection.issues}
    assert "duplicate_event" in kinds
    assert "missing_parent_event" in kinds
    assert "invalid_permission_decision" in kinds
    assert "out_of_order_events" in kinds
    assert "plaintext_secret_redacted" in kinds
    ids = [issue["id"] for issue in collection.issues]
    assert len(ids) == len(set(ids))


def test_malformed_and_conflicting_duplicates(tmp_path):
    path = tmp_path / "events.jsonl"
    base = {
        "schema_version": "1.0",
        "run_id": "r1",
        "event_id": "evt-1",
        "timestamp": "2026-01-01T00:00:00Z",
        "principal": {"id": "u", "role": "analyst"},
        "tool": "read_file",
        "args": {},
        "permission": {"decision": "allow"},
        "result": {"status": "ok"},
    }
    conflicting = {**base, "tool": "send_external"}
    lines = [
        json.dumps(base),
        "{not-json",
        json.dumps(conflicting),
        json.dumps({k: v for k, v in base.items() if k != "event_id"}),
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    result = collect_events([path])
    kinds = {issue["kind"] for issue in result.issues}
    assert "malformed_line" in kinds
    assert "conflicting_duplicate_event" in kinds
    assert "missing_field" in kinds
    assert result.stats["conflicting_duplicates"] == 1
    # The record without an event ID gets a deterministic synthetic identifier.
    assert any(event["event_id"].startswith("evt-missing-") for event in result.events)


def test_receipt_content_is_removed_and_sensitive_ids_are_preserved():
    receipts, issues = collect_receipts(
        [RECEIPTS]
    )
    assert len(receipts) == 1
    receipt = receipts[0]
    assert "content" not in receipt
    assert receipt["content_redacted"] is True
    assert "gamma-vendor-key" in receipt["sensitive_ids"]
    assert any(issue["kind"] == "plaintext_secret_redacted" for issue in issues)
    assert "DEMOSECRET" not in json.dumps(receipt)


def test_missing_time_is_kept_and_sorted_last(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "run_id": "r",
                "event_id": "evt-no-time",
                "principal": {},
                "tool": "read_file",
                "args": {},
                "permission": {"decision": "allow"},
                "result": {"status": "ok"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    result = collect_events([path])
    assert result.events[0]["event_id"] == "evt-no-time"
    assert any(issue["kind"] == "missing_timestamp" for issue in result.issues)
