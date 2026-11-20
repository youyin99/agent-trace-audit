from __future__ import annotations

from agent_trace_audit.rules import alert_counts, evaluate_rules


def test_sample_alerts_include_core_rules(audit_parts):
    alerts, _, _ = audit_parts
    rules = {alert["rule_id"] for alert in alerts}
    assert {"AUD-001", "AUD-002", "AUD-003", "AUD-004", "AUD-006", "AUD-008", "AUD-009"} <= rules
    counts = alert_counts(alerts)
    assert counts["high"] >= 3
    assert counts["low"] >= 1


def test_inconsistent_denied_but_successful_is_high(collection):
    event = {
        "event_id": "evt-inconsistent",
        "tool": "send_external",
        "origin": "user",
        "args": {"destination": "partner@partner.example.test"},
        "permission": {"decision": "deny", "reason_code": "test"},
        "result": {"status": "ok", "evidence": {}},
    }
    alerts = evaluate_rules([event], [], [])
    matching = [alert for alert in alerts if alert["rule_id"] == "AUD-005"]
    assert matching
    assert matching[0]["severity"] == "high"


def test_alerts_contain_no_secret_plaintext(audit_parts):
    alerts, _, _ = audit_parts
    assert "DEMOSECRET-GAMMA-4D1S8F6G3B9M2K7Q" not in str(alerts)
