from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from typing import Any

SECRET_RE = re.compile(r"DEMOSECRET-[A-Z0-9]+-[A-Z0-9]{16}")
BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
ZERO_WIDTH_RE = re.compile(r"[​-‏‪-‮⁠﻿]")
REDACTED = "[REDACTED:synthetic-secret]"


def fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


def _mostly_text(value: str) -> bool:
    return bool(value) and all(
        char.isprintable() or char in "\n\r\t" for char in value
    )


def _decode_base64_candidates(text: str) -> list[str]:
    candidates: list[str] = []
    for token in BASE64_TOKEN_RE.findall(text):
        padded = token + "=" * (-len(token) % 4)
        for altchars in (None, b"-_"):
            try:
                raw = base64.b64decode(padded.encode("ascii"), altchars=altchars, validate=False)
                decoded = raw.decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            if _mostly_text(decoded):
                candidates.append(decoded)
                break
    return candidates


@dataclass(frozen=True)
class ScanResult:
    secret_ids: tuple[str, ...]
    had_plaintext: bool


class Redactor:
    """Redact explicitly synthetic secrets from arbitrary event structures.

    The redactor also handles Base64 variants, zero-width character splitting,
    and common Unicode width normalization before secret matching. It never
    performs any cryptographic transformation that would allow recovering the
    original value from the report.
    """

    def scan(self, text: str) -> ScanResult:
        if not isinstance(text, str):
            return ScanResult((), False)
        normalized = unicodedata.normalize("NFKC", ZERO_WIDTH_RE.sub("", text))
        matches = [match.group(0) for match in SECRET_RE.finditer(normalized)]
        encoded_hits = []
        for token in BASE64_TOKEN_RE.findall(text):
            padded = token + "=" * (-len(token) % 4)
            for altchars in (None, b"-_"):
                try:
                    decoded = base64.b64decode(
                        padded.encode("ascii"), altchars=altchars, validate=False
                    ).decode("utf-8")
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    continue
                if SECRET_RE.search(unicodedata.normalize("NFKC", ZERO_WIDTH_RE.sub("", decoded))):
                    encoded_hits.append(token)
                break
        ids = {
            f"synthetic-{fingerprint(value)}"
            for value in matches
        }
        ids.update(f"synthetic-b64-{fingerprint(value)}" for value in encoded_hits)
        return ScanResult(tuple(sorted(ids)), bool(matches or encoded_hits))

    def redact_text(self, text: str) -> str:
        if not isinstance(text, str):
            return text
        result = text
        for token in BASE64_TOKEN_RE.findall(result):
            padded = token + "=" * (-len(token) % 4)
            try:
                decoded = base64.b64decode(
                    padded.encode("ascii"), altchars=b"-_", validate=False
                ).decode("utf-8")
            except (ValueError, UnicodeDecodeError, binascii.Error):
                continue
            normalized = unicodedata.normalize("NFKC", ZERO_WIDTH_RE.sub("", decoded))
            if SECRET_RE.search(normalized):
                result = result.replace(token, REDACTED)
        normalized_for_secret = unicodedata.normalize(
            "NFKC", ZERO_WIDTH_RE.sub("", result)
        )
        if SECRET_RE.search(normalized_for_secret):
            # Only normalize when a secret is present. This makes zero-width
            # split secrets contiguous before redaction.
            result = normalized_for_secret
        return SECRET_RE.sub(REDACTED, result)

    def redact_structure(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {str(key): self.redact_structure(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_structure(item) for item in value]
        if isinstance(value, tuple):
            return [self.redact_structure(item) for item in value]
        return value

    @staticmethod
    def contains_secret(value: Any) -> bool:
        if isinstance(value, str):
            return Redactor().scan(value).had_plaintext
        if isinstance(value, dict):
            return any(Redactor.contains_secret(item) for item in value.values())
        if isinstance(value, list):
            return any(Redactor.contains_secret(item) for item in value)
        return False
