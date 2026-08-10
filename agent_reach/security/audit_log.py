"""Structured security audit events with secret redaction."""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
from typing import Any, Dict, Optional

from .credential_guard import redact_secrets


@dataclass(frozen=True)
class AuditEvent:
    event: str
    source: str
    decision: str
    detail: str = ""
    timestamp: str = ""

    def to_json(self) -> str:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp or datetime.now(timezone.utc).isoformat()
        payload["detail"] = redact_secrets(payload["detail"])
        return json.dumps(payload, sort_keys=True)


def make_event(event: str, source: str, decision: str, detail: Optional[str] = None) -> AuditEvent:
    return AuditEvent(event=event, source=source, decision=decision, detail=detail or "")
