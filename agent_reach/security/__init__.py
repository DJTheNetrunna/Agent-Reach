"""Security primitives for hardened agent integrations.

This package is intentionally dependency-light so security checks can run before
optional channel/tool dependencies are invoked.
"""

from .content_boundary import ContentEnvelope, TrustLevel, wrap_untrusted
from .injection_guard import InjectionFinding, InjectionReport, scan_prompt_injection
from .command_policy import CommandDecision, CommandRisk, evaluate_command
from .credential_guard import redact_secrets

__all__ = [
    "ContentEnvelope",
    "TrustLevel",
    "wrap_untrusted",
    "InjectionFinding",
    "InjectionReport",
    "scan_prompt_injection",
    "CommandDecision",
    "CommandRisk",
    "evaluate_command",
    "redact_secrets",
]
