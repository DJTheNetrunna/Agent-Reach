"""Best-effort redaction for secrets before logs/model-visible diagnostics."""

import re

_PATTERNS = (
    re.compile(r"(?i)\b(authorization\s*:\s*bearer\s+)([^\s]+)"),
    re.compile(r"(?i)\b(api[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|secret)\s*[:=]\s*(['\"]?)([^\s,'\"}]+)"),
    re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,})\b"),
)


def redact_secrets(text: str) -> str:
    value = text or ""
    value = _PATTERNS[0].sub(lambda m: m.group(1) + "[REDACTED]", value)
    value = _PATTERNS[1].sub(lambda m: f"{m.group(1)}=[REDACTED]", value)
    value = _PATTERNS[2].sub("[REDACTED_GITHUB_TOKEN]", value)
    return value
