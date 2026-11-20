from __future__ import annotations

import html
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import __version__
from .collector import CollectionResult
from .correlate import CORRELATION_NOTE
from .redaction import Redactor
from .rules import RULE_CATALOG, alert_counts


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_report(
    collection: CollectionResult,
    *,
    alerts: list[dict[str, Any]],
    timeline: list[dict[str, Any]],
    provenance: list[dict[str, Any]],
    inputs: dict[str, list[str]],
) -> dict[str, Any]:
    issues_by_severity = {"high": 0, "medium": 0, "low": 0}
    for issue in collection.issues:
        if issue.get("severity") in issues_by_severity:
            issues_by_severity[issue["severity"]] += 1
    runs = sorted(
        {
            str(event.get("run_id"))
            for event in collection.events
            if event.get("run_id")
        }
    )
    report = {
        "schema_version": "1.0",
        "report_type": "agent_trace_audit",
        "tool_version": __version__,
        "generated_at": _now(),
        "inputs": inputs,
        "summary": {
            "input_event_lines": collection.stats.get("input_events", 0),
            "events": len(collection.events),
            "receipts": len(collection.receipts),
            "runs": len(runs),
            "duplicates_removed": collection.stats.get("duplicates_removed", 0),
            "conflicting_duplicates": collection.stats.get("conflicting_duplicates", 0),
            "collection_issues": len(collection.issues),
            "collection_issues_by_severity": issues_by_severity,
            "alerts": alert_counts(alerts),
            "provenance_chains": len(provenance),
        },
        "collection_issues": collection.issues,
        "alerts": alerts,
        "timeline": timeline,
        "provenance": provenance,
        "rule_catalog": RULE_CATALOG,
        "correlation_disclaimer": CORRELATION_NOTE,
        "limitations": [
            "Input events are treated as records, not trusted instructions.",
            "Correlation is based on recorded IDs, parent links, and receiver evidence; it is not a proof of causation.",
            "The redactor covers explicitly synthetic DEMOSECRET-* material and its Base64 variants.",
            "Missing or malformed records are reported and handled defensively, not silently repaired in source data.",
        ],
    }
    return Redactor().redact_structure(report)


def write_report(output_dir: Path | str, report: dict[str, Any], name: str = "audit-report") -> tuple[Path, Path]:
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / f"{name}.json"
    html_path = output / f"{name}.html"
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    html_path.write_text(render_html(report), encoding="utf-8")
    return json_path, html_path


def render_html(report: dict[str, Any]) -> str:
    summary = report["summary"]
    sev_class = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}
    alert_rows = []
    for alert in report["alerts"]:
        alert_rows.append(
            "<tr>"
            f"<td><code>{html.escape(alert['rule_id'])}</code></td>"
            f"<td><span class='badge {sev_class.get(alert['severity'], '')}'>{html.escape(alert['severity'])}</span></td>"
            f"<td>{html.escape(alert['title'])}</td>"
            f"<td>{html.escape(alert['message'])}</td>"
            f"<td><code>{html.escape(', '.join(alert.get('event_ids', [])) or '—')}</code></td>"
            f"<td><code>{html.escape(', '.join(alert.get('receipt_ids', [])) or '—')}</code></td>"
            "</tr>"
        )
    chain_cards = []
    for chain in report["provenance"]:
        source = chain.get("source_document") or {}
        permission = chain.get("permission") or {}
        execution = chain.get("execution") or {}
        receipt = chain.get("receipt") or {}
        source_label = source.get("document_id") or source.get("relative_path") or "unresolved document"
        chain_cards.append(
            f"""
<div class="chain">
  <h3>{html.escape(str(source_label))}</h3>
  <div class="flow">
    <span class="node">Source<br>{html.escape(str(source.get('origin') or 'unknown'))}</span>
    <span class="arrow">→</span>
    <span class="node">Read<br><code>{html.escape(str(chain.get('read_event_id') or '—'))}</code></span>
    <span class="arrow">→</span>
    <span class="node">Egress<br><code>{html.escape(str(chain.get('egress_event_id') or '—'))}</code></span>
    <span class="arrow">→</span>
    <span class="node">Permission<br>{html.escape(str(permission.get('decision') or 'unknown'))}<br>{html.escape(str(permission.get('reason_code') or ''))}</span>
    <span class="arrow">→</span>
    <span class="node">Receiver<br><code>{html.escape(str(receipt.get('receipt_id') or '—'))}</code></span>
  </div>
  <p><strong>Execution:</strong> {html.escape(str(execution.get('status') or 'unknown'))} · {html.escape(str(execution.get('summary') or ''))}</p>
  <p><strong>Observed sensitive identifiers:</strong> {html.escape(', '.join(chain.get('observed_sensitive_ids', [])))}</p>
  <p><strong>Destination:</strong> {html.escape(str(receipt.get('destination') or '—'))}</p>
  <p class="note">{html.escape(chain.get('correlation_note', CORRELATION_NOTE))}</p>
</div>"""
        )
    timeline_rows = []
    for item in report["timeline"]:
        timeline_rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('timestamp') or '—'))}</td>"
            f"<td><code>{html.escape(str(item.get('event_id') or '—'))}</code></td>"
            f"<td>{html.escape(str(item.get('tool') or '—'))}</td>"
            f"<td>{html.escape(str(item.get('origin') or '—'))}</td>"
            f"<td>{html.escape(str((item.get('permission') or {}).get('decision') or '—'))}</td>"
            f"<td>{html.escape(str((item.get('result') or {}).get('status') or '—'))}</td>"
            f"<td>{html.escape(str((item.get('principal') or {}).get('id') or '—'))}</td>"
            "</tr>"
        )
    issue_rows = []
    for issue in report["collection_issues"]:
        issue_rows.append(
            "<tr>"
            f"<td><code>{html.escape(issue['id'])}</code></td>"
            f"<td><span class='badge {sev_class.get(issue.get('severity'), '')}'>{html.escape(str(issue.get('severity')))}</span></td>"
            f"<td>{html.escape(str(issue.get('kind')))}</td>"
            f"<td>{html.escape(str(issue.get('message')))}</td>"
            f"<td>{html.escape(str(issue.get('location')))}</td>"
            "</tr>"
        )
    alert_count = sum(summary["alerts"].values())
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent Trace Audit</title>
<style>
:root {{ color-scheme:light; --bg:#f4f2ed; --panel:#fffdf8; --ink:#202524; --muted:#69716e; --line:#d9d5ca; --accent:#263d46; --critical:#7a1f1f; --critical-bg:#f6dedb; --high:#8c3420; --high-bg:#f9e4dc; --medium:#835c08; --medium-bg:#f8edcf; --low:#335b6b; --low-bg:#e4edf0; }}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.55 "Segoe UI",system-ui,sans-serif; }}
header {{ background:var(--accent); color:#fff; padding:36px max(20px,6vw) 30px; }}
header .eyebrow {{ opacity:.72; font-size:12px; letter-spacing:.12em; text-transform:uppercase; }}
h1 {{ margin:6px 0; font-size:clamp(28px,4vw,44px); }}
header p {{ max-width:900px; opacity:.85; }}
main {{ max-width:1220px; margin:0 auto; padding:24px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(135px,1fr)); gap:12px; margin:-46px 0 22px; }}
.card {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:15px; box-shadow:0 8px 24px rgba(38,61,70,.08); }}
.card b {{ display:block; font-size:28px; color:var(--accent); }}
.card span {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.06em; }}
section {{ background:var(--panel); border:1px solid var(--line); border-radius:12px; padding:20px; margin:16px 0; }}
h2 {{ margin:0 0 12px; font-size:21px; }}
h3 {{ margin:0 0 10px; }}
table {{ width:100%; border-collapse:collapse; display:block; overflow-x:auto; }}
th,td {{ text-align:left; padding:9px 10px; border-bottom:1px solid var(--line); vertical-align:top; }}
th {{ color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em; }}
code {{ background:#ebe7dc; padding:1px 4px; border-radius:4px; font-size:.9em; overflow-wrap:anywhere; }}
.badge {{ display:inline-block; border-radius:999px; padding:2px 8px; font-size:11px; font-weight:700; }}
.critical {{ color:var(--critical); background:var(--critical-bg); }}
.high {{ color:var(--high); background:var(--high-bg); }}
.medium {{ color:var(--medium); background:var(--medium-bg); }}
.low {{ color:var(--low); background:var(--low-bg); }}
.chain {{ border:1px solid var(--line); border-radius:10px; padding:16px; margin:12px 0; background:#fff; }}
.flow {{ display:flex; flex-wrap:wrap; align-items:center; gap:8px; margin:10px 0; }}
.node {{ border:1px solid var(--line); border-radius:8px; padding:7px 9px; font-size:12px; background:#f7f4ed; }}
.arrow {{ color:var(--muted); }}
.note {{ font-size:12px; color:var(--muted); }}
.muted {{ color:var(--muted); }}
footer {{ color:var(--muted); font-size:12px; margin:20px 0 40px; }}
@media (max-width:640px) {{ main {{ padding:16px; }} header {{ padding:28px 18px; }} .cards {{ margin-top:16px; }} }}
</style>
</head>
<body>
<header>
  <div class="eyebrow">Evidence correlation · not a causal proof</div>
  <h1>Agent Trace Audit</h1>
  <p>Events are validated, deduplicated, sorted, redacted, and correlated with receiver evidence. The report preserves identifiers and hashes, never synthetic secret plaintext.</p>
</header>
<main>
  <div class="cards">
    <div class="card"><b>{summary['events']}</b><span>Events</span></div>
    <div class="card"><b>{summary['receipts']}</b><span>Receipts</span></div>
    <div class="card"><b>{alert_count}</b><span>Alerts</span></div>
    <div class="card"><b>{summary['provenance_chains']}</b><span>Provenance chains</span></div>
    <div class="card"><b>{summary['duplicates_removed']}</b><span>Duplicates removed</span></div>
    <div class="card"><b>{summary['collection_issues']}</b><span>Collection issues</span></div>
  </div>
  <section>
    <h2>Alerts</h2>
    <table>
      <thead><tr><th>Rule</th><th>Severity</th><th>Title</th><th>Message</th><th>Events</th><th>Receipts</th></tr></thead>
      <tbody>{''.join(alert_rows) or '<tr><td colspan="6">No alerts.</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Provenance associations</h2>
    <p class="muted">{html.escape(report['correlation_disclaimer'])}</p>
    {''.join(chain_cards) or '<p>No sensitive receiver evidence was found.</p>'}
  </section>
  <section>
    <h2>Timeline</h2>
    <table>
      <thead><tr><th>Timestamp</th><th>Event</th><th>Tool</th><th>Origin</th><th>Permission</th><th>Result</th><th>Principal</th></tr></thead>
      <tbody>{''.join(timeline_rows) or '<tr><td colspan="7">No events.</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Collection issues</h2>
    <table>
      <thead><tr><th>ID</th><th>Severity</th><th>Kind</th><th>Message</th><th>Location</th></tr></thead>
      <tbody>{''.join(issue_rows) or '<tr><td colspan="5">None.</td></tr>'}</tbody>
    </table>
  </section>
  <section>
    <h2>Scope and limitations</h2>
    <ul>{''.join(f'<li>{html.escape(item)}</li>' for item in report['limitations'])}</ul>
    <p class="muted">Generated {html.escape(report['generated_at'])} · agent-trace-audit {html.escape(report['tool_version'])}</p>
  </section>
  <footer>All displayed values are redacted. Correlation is an investigative aid, not proof of causation.</footer>
</main>
</body>
</html>
"""
