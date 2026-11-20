from __future__ import annotations

from pathlib import Path

import pytest

from agent_trace_audit.collector import collect_events, collect_receipts, merge_collection
from agent_trace_audit.correlate import build_provenance, build_timeline
from agent_trace_audit.redaction import Redactor
from agent_trace_audit.report import build_report
from agent_trace_audit.rules import evaluate_rules

REPO_ROOT = Path(__file__).resolve().parents[1]
EVENTS = REPO_ROOT / "fixtures" / "events.jsonl"
RECEIPTS = REPO_ROOT / "fixtures" / "receipts.jsonl"


@pytest.fixture(scope="session")
def collection():
    redactor = Redactor()
    events = collect_events([EVENTS], redactor)
    receipts, receipt_issues = collect_receipts([RECEIPTS], redactor)
    return merge_collection(events, receipts, receipt_issues)


@pytest.fixture(scope="session")
def audit_parts(collection):
    alerts = evaluate_rules(collection.events, collection.receipts, collection.issues)
    timeline = build_timeline(collection.events)
    provenance = build_provenance(collection.events, collection.receipts)
    return alerts, timeline, provenance


@pytest.fixture(scope="session")
def audit_report(collection, audit_parts):
    alerts, timeline, provenance = audit_parts
    return build_report(
        collection,
        alerts=alerts,
        timeline=timeline,
        provenance=provenance,
        inputs={"events": ["events.jsonl"], "receipts": ["receipts.jsonl"]},
    )
