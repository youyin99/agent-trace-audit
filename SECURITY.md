# Security Policy

## Scope

Agent Trace Audit processes local JSONL events and receipt summaries. It does not
connect to remote systems. Its output is an investigative association, not a
forensic proof or a causal finding.

## Reporting

Use a private GitHub Security Advisory for this repository.

Include:

- affected version/commit;
- a minimal synthetic event/receipt reproduction;
- whether plaintext synthetic secret material appears in output;
- whether missing/duplicate data could produce a misleading association;
- the affected report field or rule.

## In scope

- raw synthetic secret in JSON, HTML, collected events, or receipts;
- Base64 or zero-width secret bypass of the redactor;
- provenance claiming causation or hiding the disclaimer;
- malformed input causing a crash or silent data loss;
- HTML/report injection;
- collection issue or alert ID collision.

## Out of scope

- production credential scanning;
- forged source events by an actor with write access to input;
- SIEM/database integration;
- proving causality in an incident;
- complete coverage of all possible timestamp ambiguities.
