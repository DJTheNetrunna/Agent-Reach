"""Conservative heuristic detector for indirect prompt-injection indicators.

This is a signal generator, not a claim that regex can solve prompt injection.
Callers should combine findings with trust boundaries and action authorization.
"""

from dataclasses import dataclass
import re
from typing import Tuple


@dataclass(frozen=True)
class InjectionFinding:
    rule: str
    severity: str
    excerpt: str


@dataclass(frozen=True)
class InjectionReport:
    suspicious: bool
    score: int
    findings: Tuple[InjectionFinding, ...]


_RULES = (
    ("instruction_override", "high", r"(?i)\b(ignore|disregard|forget|override)\b.{0,80}\b(previous|prior|system|developer|instructions?|prompt)\b"),
    ("role_impersonation", "medium", r"(?im)^\s*(system|developer|assistant)\s*[:>]"),
    ("secret_request", "high", r"(?i)\b(reveal|print|show|send|upload|exfiltrat\w*)\b.{0,100}\b(password|token|secret|cookie|credential|api[_ -]?key|ssh[_ -]?key)\b"),
    ("tool_coercion", "high", r"(?i)\b(run|execute|invoke|call|launch)\b.{0,80}\b(shell|terminal|bash|powershell|tool|command|sudo)\b"),
    ("remote_pipe_shell", "critical", r"(?i)\b(curl|wget)\b[^\n]{0,200}\|\s*(sh|bash|zsh)\b"),
    ("security_disable", "critical", r"(?i)\b(disable|bypass|turn off|remove)\b.{0,100}\b(security|firewall|antivirus|guard|policy|sandbox|protection)\b"),
)


def scan_prompt_injection(text: str) -> InjectionReport:
    findings = []
    weights = {"medium": 2, "high": 4, "critical": 7}
    score = 0
    for name, severity, pattern in _RULES:
        match = re.search(pattern, text or "")
        if match:
            excerpt = match.group(0).replace("\n", " ")[:240]
            findings.append(InjectionFinding(name, severity, excerpt))
            score += weights[severity]
    return InjectionReport(bool(findings), score, tuple(findings))
