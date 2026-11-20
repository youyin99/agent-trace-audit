# Agent Trace Audit

Redacted agent event collection, validation, timeline generation, rule alerts, and provenance-style correlation.

The audit reads JSONL execution events plus optional local-receiver receipts and produces a versioned JSON report and static HTML report. It handles:

- out-of-order timestamps;
- identical duplicates;
- conflicting duplicate event IDs;
- missing fields, timestamps, parents, permission decisions, and results;
- malformed JSONL lines;
- plaintext synthetic secrets in input (redacted before output);
- sensitive receiver evidence and related tool calls;
- association of an external document → file read → egress call → permission decision → actual result → receiver receipt.

The report never states that the association proves causation.

## Requirements

- Python 3.11–3.13
- No runtime dependencies; `pytest` for tests

## Install

```bash
python -m pip install -e ".[dev]"
```

## Quick start

```bash
python -m agent_trace_audit audit \
  --events fixtures/events.jsonl \
  --receipts fixtures/receipts.jsonl \
  --out examples/output
```

Expected:

```text
events=7 receipts=1 alerts=10 high=3 critical=0 chains=1 issues=6
```

Outputs:

- `examples/output/audit-report.json`
- `examples/output/audit-report.html`
- `examples/output/events.redacted.jsonl`
- `examples/output/receipts.redacted.jsonl`

A generated sample is committed under [`examples/output/`](examples/output/). The
raw fixture intentionally includes a synthetic secret to exercise redaction; the
produced logs and reports contain no plaintext secret.

`--fail-on-high` makes the CLI exit `1` when a high/critical alert exists.

## Architecture

```text
events JSONL ─┐
receipts JSONL┼─> validation / dedupe / sort / redaction
              │             │
              │             ├─ collection issues
              │             ├─ timeline
              │             ├─ rule alerts
              │             └─ provenance correlation
              │                          │
              ▼                          ▼
    redacted JSONL artifacts      JSON + HTML report
```

The detailed Chinese design is in [`docs/DESIGN.zh-CN.md`](docs/DESIGN.zh-CN.md).

## Reproduce the sample

```bash
python -m agent_trace_audit audit \
  --events fixtures/events.jsonl \
  --receipts fixtures/receipts.jsonl \
  --out examples/output
```

The generated `audit-report.json`, `audit-report.html`, and redacted JSONL files
should match the committed sample semantically. The CLI reports the counts and
returns `0` unless `--fail-on-high` is supplied.

## Collect only

```bash
python -m agent_trace_audit collect \
  --events fixtures/events.jsonl \
  --receipts fixtures/receipts.jsonl \
  --out collected
```

This writes deduplicated, sorted, redacted JSONL with raw receipt content
removed. It is useful as a sanitization stage before storage or review.

## Detection and alerts

| Rule | Severity | Trigger |
|---|---|---|
| `AUD-001` | medium | Missing/invalid permission decision |
| `AUD-002` | low | Egress attempt denied |
| `AUD-003` | high | Successful egress from untrusted origin |
| `AUD-004` | high | Successful egress carrying sensitive IDs |
| `AUD-005` | high | Denied action with successful result |
| `AUD-006` | high | Receiver records sensitive IDs |
| `AUD-007` | high | Conflicting duplicate event |
| `AUD-008` | medium | Referenced parent missing |
| `AUD-009` | medium | Plaintext synthetic secret in input, redacted |

## Provenance chain

For a receiver receipt with sensitive IDs, the audit:

1. finds the linked egress event (by `event_id`, then by `receipt_id` evidence);
2. follows parent/derived event links to a read event;
3. prefers a read whose evidence marks the source as external;
4. copies the permission decision (allow/deny, reason code, policy version);
5. copies the execution status and summary;
6. links the receipt, destination, observed sensitive identifiers, and hashes;
7. adds the fixed correlation disclaimer.

The chain is an investigative association, not a complete forensic proof. It can
only use identifiers and links that were recorded.

## Redaction

The redactor handles:

- `DEMOSECRET-*` synthetic values;
- Base64 variants;
- zero-width split characters;
- Unicode NFKC variants.

It stores only opaque identifiers such as `synthetic-<hash>`; raw content is
removed from collected receipts. The report is redacted again as a final guard.

## Tests

```bash
python -m pytest
```

Coverage includes deduplication, sorting, missing field/parent handling, malformed
input, conflicting duplicates, receipt sanitization, direct/Base64/zero-width
redaction, rule alerts, provenance fields, the disclaimer, HTML escaping, CLI
outputs, and `--fail-on-high`.

## Known limitations

- Correlation is evidence association, not causal proof.
- The redactor recognizes explicitly synthetic secret shapes; it is not a general
  secrets scanner for real production credentials.
- Input event sources are trusted to record IDs honestly; forged events can
  mislead correlation.
- No database, search index, real-time stream, or remote log ingestion.
- No claim of complete coverage of missing-order ambiguity.

## Contributing and security reports

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
