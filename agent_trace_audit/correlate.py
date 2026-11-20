from __future__ import annotations

from typing import Any

from .redaction import Redactor

CORRELATION_NOTE = (
    "Associated from recorded parent/event identifiers and receiver evidence. "
    "This is not a proof of causation."
)


def build_timeline(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    redactor = Redactor()
    timeline = []
    for event in events:
        permission = event.get("permission") or {}
        result = event.get("result") or {}
        principal = event.get("principal") or {}
        timeline.append(
            redactor.redact_structure(
                {
                    "timestamp": event.get("timestamp"),
                    "event_id": event.get("event_id"),
                    "run_id": event.get("run_id"),
                    "sequence": event.get("sequence"),
                    "parent_event_id": event.get("parent_event_id"),
                    "principal": {
                        "id": principal.get("id"),
                        "role": principal.get("role"),
                    },
                    "tool": event.get("tool"),
                    "origin": event.get("origin"),
                    "permission": {
                        "decision": permission.get("decision"),
                        "reason_code": permission.get("reason_code"),
                        "policy_version": permission.get("policy_version"),
                    },
                    "result": {
                        "status": result.get("status"),
                        "summary": result.get("summary"),
                    },
                }
            )
        )
    return timeline


def _read_ancestors(event: dict[str, Any], by_id: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    ancestors: list[dict[str, Any]] = []
    visited: set[str] = set()
    stack: list[str] = []
    parent = event.get("parent_event_id")
    if isinstance(parent, str):
        stack.append(parent)
    evidence = (event.get("result") or {}).get("evidence")
    if isinstance(evidence, dict):
        derived = evidence.get("derived_from_event_ids")
        if isinstance(derived, list):
            stack.extend(item for item in derived if isinstance(item, str))
    while stack and len(ancestors) < 20:
        event_id = stack.pop()
        if event_id in visited:
            continue
        visited.add(event_id)
        ancestor = by_id.get(event_id)
        if ancestor is None:
            continue
        ancestors.append(ancestor)
        next_parent = ancestor.get("parent_event_id")
        if isinstance(next_parent, str):
            stack.append(next_parent)
    return ancestors


def build_provenance(
    events: list[dict[str, Any]],
    receipts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id = {event["event_id"]: event for event in events}
    by_receipt = {}
    for event in events:
        evidence = (event.get("result") or {}).get("evidence")
        if isinstance(evidence, dict) and isinstance(evidence.get("receipt_id"), str):
            by_receipt[evidence["receipt_id"]] = event
    chains: list[dict[str, Any]] = []
    seen_receipts: set[str] = set()
    for receipt in receipts:
        sensitive = receipt.get("sensitive_ids") or []
        if not sensitive:
            continue
        receipt_id = str(receipt.get("receipt_id", ""))
        if not receipt_id or receipt_id in seen_receipts:
            continue
        seen_receipts.add(receipt_id)
        linked_event_id = receipt.get("event_id")
        send_event = by_id.get(linked_event_id) if isinstance(linked_event_id, str) else None
        if send_event is None:
            send_event = by_receipt.get(receipt_id)
        read_events = _read_ancestors(send_event, by_id) if send_event else []
        reads = [event for event in read_events if event.get("tool") == "read_file"]
        external_reads = []
        for read_event in reads:
            evidence = (read_event.get("result") or {}).get("evidence") or {}
            source = evidence.get("source") if isinstance(evidence, dict) else None
            if isinstance(source, dict) and source.get("origin") == "external":
                external_reads.append(read_event)
        selected_read = (external_reads or reads or [None])[0]
        source_document = None
        read_event_id = None
        if selected_read:
            read_event_id = selected_read.get("event_id")
            evidence = (selected_read.get("result") or {}).get("evidence") or {}
            source = evidence.get("source") if isinstance(evidence, dict) else None
            if isinstance(source, dict):
                source_document = {
                    "document_id": source.get("document_id"),
                    "origin": source.get("origin"),
                    "publisher": source.get("publisher"),
                    "relative_path": evidence.get("relative_path"),
                }
            else:
                source_document = {
                    "document_id": None,
                    "origin": "internal-or-unknown",
                    "relative_path": evidence.get("relative_path"),
                }
        permission = (send_event or {}).get("permission") or {}
        result = (send_event or {}).get("result") or {}
        event_sensitive = []
        evidence = result.get("evidence") if isinstance(result, dict) else None
        if isinstance(evidence, dict) and isinstance(evidence.get("sensitive_ids"), list):
            event_sensitive = [
                str(item) for item in evidence["sensitive_ids"] if isinstance(item, str)
            ]
        observed = sorted(set(map(str, sensitive)) | set(event_sensitive))
        chains.append(
            {
                "source_document": source_document,
                "read_event_id": read_event_id,
                "egress_event_id": (send_event or {}).get("event_id"),
                "permission": {
                    "decision": permission.get("decision"),
                    "reason_code": permission.get("reason_code"),
                    "policy_version": permission.get("policy_version"),
                },
                "execution": {
                    "status": result.get("status"),
                    "summary": result.get("summary"),
                },
                "receipt": {
                    "receipt_id": receipt_id,
                    "destination": receipt.get("destination"),
                    "content_redacted": bool(receipt.get("content_redacted")),
                },
                "observed_sensitive_ids": observed,
                "correlation_note": CORRELATION_NOTE,
            }
        )
    chains.sort(
        key=lambda chain: (
            str(chain["egress_event_id"] or ""),
            str(chain["receipt"]["receipt_id"] or ""),
        )
    )
    return Redactor().redact_structure(chains)
