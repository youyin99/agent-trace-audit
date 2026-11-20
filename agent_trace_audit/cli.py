from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .collector import collect_events, collect_receipts, merge_collection
from .correlate import build_provenance, build_timeline
from .errors import TraceAuditError
from .redaction import Redactor
from .report import build_report, write_report
from .rules import evaluate_rules


def _collect(events_paths: list[str], receipt_paths: list[str]):
    redactor = Redactor()
    events_result = collect_events(events_paths, redactor)
    receipts, receipt_issues = (
        collect_receipts(receipt_paths, redactor) if receipt_paths else ([], [])
    )
    return merge_collection(events_result, receipts, receipt_issues)


def command_audit(args: argparse.Namespace) -> int:
    collection = _collect(args.events, args.receipts)
    alerts = evaluate_rules(collection.events, collection.receipts, collection.issues)
    timeline = build_timeline(collection.events)
    provenance = build_provenance(collection.events, collection.receipts)
    report = build_report(
        collection,
        alerts=alerts,
        timeline=timeline,
        provenance=provenance,
        inputs={
            "events": [Path(path).name for path in args.events],
            "receipts": [Path(path).name for path in args.receipts],
        },
    )
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    collection.write_events(output / "events.redacted.jsonl")
    collection.write_receipts(output / "receipts.redacted.jsonl")
    json_path, html_path = write_report(output, report, name=args.name)
    counts = report["summary"]["alerts"]
    print(
        f"events={len(collection.events)} receipts={len(collection.receipts)} "
        f"alerts={sum(counts.values())} high={counts['high']} critical={counts['critical']} "
        f"chains={len(provenance)} issues={len(collection.issues)} report={json_path}"
    )
    if args.fail_on_high and (counts["high"] or counts["critical"]):
        return 1
    return 0


def command_collect(args: argparse.Namespace) -> int:
    collection = _collect(args.events, args.receipts)
    output = Path(args.out)
    output.mkdir(parents=True, exist_ok=True)
    collection.write_events(output / args.events_name)
    collection.write_receipts(output / args.receipts_name)
    print(
        f"events={len(collection.events)} receipts={len(collection.receipts)} "
        f"issues={len(collection.issues)} output={output}"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-trace-audit",
        description="Redact, validate, correlate, and report agent execution events",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="build an audit report and provenance chains")
    audit.add_argument("--events", action="append", required=True, help="event JSONL (repeatable)")
    audit.add_argument("--receipts", action="append", default=[], help="receipt JSONL (repeatable)")
    audit.add_argument("--out", default="reports")
    audit.add_argument("--name", default="audit-report")
    audit.add_argument("--fail-on-high", action="store_true")
    audit.set_defaults(func=command_audit)

    collect = sub.add_parser("collect", help="write deduplicated, sorted, redacted JSONL")
    collect.add_argument("--events", action="append", required=True)
    collect.add_argument("--receipts", action="append", default=[])
    collect.add_argument("--out", default="collected")
    collect.add_argument("--events-name", default="events.redacted.jsonl")
    collect.add_argument("--receipts-name", default="receipts.redacted.jsonl")
    collect.set_defaults(func=command_collect)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (TraceAuditError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
