from __future__ import annotations

from agent_trace_audit.correlate import CORRELATION_NOTE


def test_provenance_links_document_read_egress_permission_receipt(audit_parts):
    _, _, provenance = audit_parts
    assert len(provenance) == 1
    chain = provenance[0]
    assert chain["source_document"]["document_id"] == "vendor-memo"
    assert chain["source_document"]["origin"] == "external"
    assert chain["read_event_id"] == "evt-read-1"
    assert chain["egress_event_id"] == "evt-send-1"
    assert chain["permission"]["decision"] == "allow"
    assert chain["permission"]["reason_code"] == "destination_allowlisted"
    assert chain["execution"]["status"] == "ok"
    assert chain["receipt"]["receipt_id"] == "rcpt-demo-1"
    assert "gamma-vendor-key" in chain["observed_sensitive_ids"]


def test_correlation_disclaimer(audit_parts, audit_report):
    _, _, provenance = audit_parts
    assert provenance[0]["correlation_note"] == CORRELATION_NOTE
    assert "not a proof of causation" in CORRELATION_NOTE
    assert "not a proof of causation" in audit_report["correlation_disclaimer"].lower()


def test_only_sensitive_receipts_produce_chains(collection):
    from agent_trace_audit.correlate import build_provenance

    safe_receipt = {
        "receipt_id": "rcpt-safe",
        "event_id": "evt-send-1",
        "destination": "partner@partner.example.test",
        "sensitive_ids": [],
    }
    assert build_provenance(collection.events, [safe_receipt]) == []
