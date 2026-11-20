from __future__ import annotations

import base64
import json
import re

from agent_trace_audit.redaction import REDACTED, Redactor, fingerprint

SECRET = "DEMOSECRET-GAMMA-4D1S8F6G3B9M2K7Q"
SECRET_RE = re.compile(r"DEMOSECRET-[A-Z0-9]+-[A-Z0-9]{16}")


def test_direct_secret_is_redacted():
    redactor = Redactor()
    text = f"body {SECRET} trailing"
    result = redactor.redact_text(text)
    assert SECRET not in result
    assert REDACTED in result
    assert redactor.scan(text).had_plaintext is True


def test_base64_secret_is_redacted():
    encoded = base64.b64encode(f"with {SECRET} inside".encode()).decode()
    result = Redactor().redact_text(encoded)
    assert encoded not in result
    assert SECRET not in result
    assert REDACTED in result


def test_zero_width_secret_is_redacted():
    split = f"DEMO​SECRET-​GAMMA-​4D1S8F6G3B9M2K7Q"
    result = Redactor().redact_text(split)
    assert SECRET_RE.search(result) is None
    assert REDACTED in result


def test_structure_redaction_preserves_shape():
    value = {
        "args": {"content": f"token={SECRET}"},
        "list": [f"x {SECRET}", 5, None],
    }
    redacted = Redactor().redact_structure(value)
    assert redacted["args"]["content"] == f"token={REDACTED}"
    assert redacted["list"][1] == 5
    assert SECRET not in json.dumps(redacted)


def test_scan_ids_never_contain_the_secret():
    result = Redactor().scan(SECRET)
    assert result.had_plaintext
    assert result.secret_ids
    assert all("DEMOSECRET" not in item for item in result.secret_ids)
    assert result.secret_ids == (f"synthetic-{fingerprint(SECRET)}",)


def test_non_secret_text_is_unchanged():
    text = "Normal text with full-width characters：and no secrets."
    assert Redactor().redact_text(text) == text
