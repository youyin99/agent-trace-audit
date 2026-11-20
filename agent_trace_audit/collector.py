from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Iterable

from .redaction import Redactor

REQUIRED_EVENT_FIELDS = (
    "schema_version",
    "run_id",
    "event_id",
    "timestamp",
    "principal",
    "tool",
    "args",
    "permission",
    "result",
)
VALID_PERMISSION = {"allow", "deny"}
VALID_RESULT = {"ok", "denied", "error", "skipped"}


@dataclass
class CollectionResult:
    events: list[dict[str, Any]] = field(default_factory=list)
    receipts: list[dict[str, Any]] = field(default_factory=list)
    issues: list[dict[str, Any]] = field(default_factory=list)
    stats: dict[str, int] = field(default_factory=dict)
    input_event_lines: int = 0
    input_receipt_lines: int = 0

    def write_events(self, path: Path | str) -> None:
        _write_jsonl(path, self.events)

    def write_receipts(self, path: Path | str) -> None:
        _write_jsonl(path, self.receipts)


def _write_jsonl(path: Path | str, records: Iterable[dict[str, Any]]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records),
        encoding="utf-8",
    )


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _issue(
    issues: list[dict[str, Any]],
    *,
    kind: str,
    severity: str,
    message: str,
    location: str,
    event_id: str | None = None,
) -> None:
    issues.append(
        {
            "id": f"collect-{len(issues) + 1:04d}",
            "kind": kind,
            "severity": severity,
            "message": message,
            "location": location,
            "event_id": event_id,
        }
    )


def _read_jsonl(paths: Iterable[Path | str], issues: list[dict[str, Any]], *, label: str):
    for path_value in paths:
        path = Path(path_value)
        try:
            text = path.read_text(encoding="utf-8-sig")
        except OSError as exc:
            _issue(
                issues,
                kind="input_error",
                severity="high",
                message=f"cannot read {label} input: {exc}",
                location=path.name,
            )
            continue
        for line_no, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            location = f"{path.name}:{line_no}"
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                _issue(
                    issues,
                    kind="malformed_line",
                    severity="medium",
                    message=f"invalid JSON at line {line_no}: {exc.msg}",
                    location=location,
                )
                continue
            if not isinstance(value, dict):
                _issue(
                    issues,
                    kind="malformed_line",
                    severity="medium",
                    message="JSONL record is not an object",
                    location=location,
                )
                continue
            yield location, value


def _normalize_event(
    raw: dict[str, Any],
    *,
    location: str,
    issues: list[dict[str, Any]],
    redactor: Redactor,
) -> tuple[dict[str, Any], datetime | None, int]:
    if Redactor.contains_secret(raw):
        _issue(
            issues,
            kind="plaintext_secret_redacted",
            severity="medium",
            message="plaintext synthetic secret was detected in the input and redacted",
            location=location,
            event_id=raw.get("event_id") if isinstance(raw.get("event_id"), str) else None,
        )
    for field_name in REQUIRED_EVENT_FIELDS:
        if field_name not in raw:
            _issue(
                issues,
                kind="missing_field",
                severity="medium" if field_name not in {"event_id", "permission", "result"} else "high",
                message=f"event is missing required field '{field_name}'",
                location=location,
                event_id=raw.get("event_id") if isinstance(raw.get("event_id"), str) else None,
            )
    event = redactor.redact_structure(raw)
    event.setdefault("schema_version", "1.0")
    event.setdefault("run_id", "unknown-run")
    if not isinstance(event.get("event_id"), str) or not event["event_id"]:
        event["event_id"] = f"evt-missing-{hashlib.sha256(location.encode()).hexdigest()[:12]}"
    if not isinstance(event.get("timestamp"), str):
        event["timestamp"] = ""
    if not isinstance(event.get("principal"), dict):
        event["principal"] = {}
    if not isinstance(event.get("tool"), str):
        event["tool"] = ""
    if not isinstance(event.get("args"), dict):
        event["args"] = {}
    if not isinstance(event.get("permission"), dict):
        event["permission"] = {}
    else:
        decision = event["permission"].get("decision")
        if decision not in VALID_PERMISSION:
            _issue(
                issues,
                kind="invalid_permission_decision",
                severity="high",
                message="permission.decision is missing or invalid",
                location=location,
                event_id=event["event_id"],
            )
    if not isinstance(event.get("result"), dict):
        event["result"] = {}
    else:
        status = event["result"].get("status")
        if status not in VALID_RESULT:
            _issue(
                issues,
                kind="invalid_result_status",
                severity="medium",
                message="result.status is missing or invalid",
                location=location,
                event_id=event["event_id"],
            )
    parent = event.get("parent_event_id")
    if parent is not None and not isinstance(parent, str):
        _issue(
            issues,
            kind="invalid_parent",
            severity="medium",
            message="parent_event_id is not a string",
            location=location,
            event_id=event["event_id"],
        )
        event["parent_event_id"] = None
    sequence = event.get("sequence", 0)
    if not isinstance(sequence, int) or isinstance(sequence, bool):
        sequence = 0
    return event, _parse_time(event.get("timestamp")), sequence


def collect_events(paths: Iterable[Path | str], redactor: Redactor | None = None) -> CollectionResult:
    redactor = redactor or Redactor()
    issues: list[dict[str, Any]] = []
    records: list[tuple[dict[str, Any], datetime | None, int, int]] = []
    input_lines = 0
    duplicates_removed = 0
    conflicting_duplicates = 0
    seen: dict[str, str] = {}
    for location, raw in _read_jsonl(paths, issues, label="event"):
        input_lines += 1
        event, timestamp, sequence = _normalize_event(
            raw, location=location, issues=issues, redactor=redactor
        )
        canonical = _canonical(event)
        event_id = event["event_id"]
        if event_id in seen:
            if seen[event_id] == canonical:
                duplicates_removed += 1
                _issue(
                    issues,
                    kind="duplicate_event",
                    severity="low",
                    message="identical duplicate event was removed",
                    location=location,
                    event_id=event_id,
                )
            else:
                conflicting_duplicates += 1
                _issue(
                    issues,
                    kind="conflicting_duplicate_event",
                    severity="high",
                    message="event ID appears with conflicting content; first record retained",
                    location=location,
                    event_id=event_id,
                )
            continue
        seen[event_id] = canonical
        records.append((event, timestamp, sequence, input_lines))

    known_times = [timestamp for _, timestamp, _, _ in records if timestamp is not None]
    out_of_order = 0
    last = None
    for timestamp in known_times:
        if last is not None and timestamp < last:
            out_of_order += 1
        if last is None or timestamp > last:
            last = timestamp
    if out_of_order:
        _issue(
            issues,
            kind="out_of_order_events",
            severity="low",
            message=f"{out_of_order} event timestamp(s) were earlier than a preceding event",
            location="event inputs",
        )
    if any(timestamp is None for _, timestamp, _, _ in records):
        _issue(
            issues,
            kind="missing_timestamp",
            severity="medium",
            message="one or more events have no usable timestamp; sorted last",
            location="event inputs",
        )

    def sort_key(item):
        event, timestamp, sequence, order = item
        if timestamp is None:
            return (1, datetime.max.replace(tzinfo=UTC), order, event["event_id"])
        return (0, timestamp, sequence, order, event["event_id"])

    records.sort(key=sort_key)
    events = [event for event, _, _, _ in records]
    event_ids = {event["event_id"] for event in events}
    for event in events:
        parent = event.get("parent_event_id")
        if parent and parent == event["event_id"]:
            _issue(
                issues,
                kind="missing_parent_event",
                severity="medium",
                message="event references itself as its parent",
                location="event inputs",
                event_id=event["event_id"],
            )
        elif parent and parent not in event_ids:
            _issue(
                issues,
                kind="missing_parent_event",
                severity="medium",
                message=f"parent event '{parent}' is not present",
                location="event inputs",
                event_id=event["event_id"],
            )
    stats = {
        "input_events": input_lines,
        "events": len(events),
        "duplicates_removed": duplicates_removed,
        "conflicting_duplicates": conflicting_duplicates,
        "out_of_order_events": out_of_order,
        "issues": len(issues),
    }
    return CollectionResult(
        events=events,
        issues=issues,
        stats=stats,
        input_event_lines=input_lines,
    )


def collect_receipts(
    paths: Iterable[Path | str],
    redactor: Redactor | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    redactor = redactor or Redactor()
    issues: list[dict[str, Any]] = []
    receipts: list[dict[str, Any]] = []
    seen: dict[str, str] = {}
    for location, raw in _read_jsonl(paths, issues, label="receipt"):
        receipt_id = raw.get("receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            receipt_id = f"rcpt-missing-{hashlib.sha256(location.encode()).hexdigest()[:12]}"
            _issue(
                issues,
                kind="missing_field",
                severity="medium",
                message="receipt is missing a receipt_id",
                location=location,
            )
        sensitive_ids = raw.get("sensitive_ids", [])
        if not isinstance(sensitive_ids, list):
            sensitive_ids = []
        sensitive_ids = {str(item) for item in sensitive_ids if isinstance(item, str)}
        raw_content = raw.get("content")
        if isinstance(raw_content, str):
            scan = redactor.scan(raw_content)
            if scan.had_plaintext:
                _issue(
                    issues,
                    kind="plaintext_secret_redacted",
                    severity="medium",
                    message="plaintext synthetic secret was detected in a receipt and redacted",
                    location=location,
                    event_id=raw.get("event_id") if isinstance(raw.get("event_id"), str) else None,
                )
            sensitive_ids.update(scan.secret_ids)
        sanitized = {
            key: redactor.redact_structure(value)
            for key, value in raw.items()
            if key != "content"
        }
        sanitized["receipt_id"] = receipt_id
        sanitized["sensitive_ids"] = sorted(sensitive_ids)
        sanitized["content_redacted"] = isinstance(raw_content, str)
        canonical = _canonical(sanitized)
        if receipt_id in seen:
            if seen[receipt_id] == canonical:
                _issue(
                    issues,
                    kind="duplicate_receipt",
                    severity="low",
                    message="duplicate receipt was removed",
                    location=location,
                )
            else:
                _issue(
                    issues,
                    kind="conflicting_duplicate_receipt",
                    severity="high",
                    message="receipt ID appears with conflicting content; first record retained",
                    location=location,
                )
            continue
        seen[receipt_id] = canonical
        receipts.append(sanitized)
    receipts.sort(
        key=lambda receipt: (
            str(receipt.get("timestamp", "")),
            str(receipt.get("receipt_id", "")),
        )
    )
    return receipts, issues


def merge_collection(
    events_result: CollectionResult,
    receipts: list[dict[str, Any]],
    receipt_issues: list[dict[str, Any]] | None = None,
) -> CollectionResult:
    issues = list(events_result.issues) + list(receipt_issues or [])
    for index, issue in enumerate(issues, start=1):
        issue["id"] = f"collect-{index:04d}"
    return CollectionResult(
        events=events_result.events,
        receipts=receipts,
        issues=issues,
        stats={
            **events_result.stats,
            "receipts": len(receipts),
            "issues": len(issues),
        },
        input_event_lines=events_result.input_event_lines,
    )
