# Contributing

## Setup

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m agent_trace_audit audit --events fixtures/events.jsonl --receipts fixtures/receipts.jsonl --out /tmp/audit
```

## Invariants

Changes must preserve:

- no synthetic secret plaintext in any produced log, JSON, or HTML;
- `uncertain` data is not silently filled in or treated as proven;
- conflicting duplicates are surfaced, not hidden;
- provenance includes the non-causation disclaimer;
- raw receipt content is removed from collected output;
- event inputs are treated as data, never instructions.

Add regression tests for missing, malformed, duplicate, and out-of-order data.

## Security reports

See [`SECURITY.md`](SECURITY.md).
