"""Small deny/approval policy for commands proposed by an agent."""

from dataclasses import dataclass
from enum import IntEnum
import re


class CommandRisk(IntEnum):
    SAFE_READ = 0
    WRITE = 1
    PRIVILEGED = 2
    BLOCKED = 3


@dataclass(frozen=True)
class CommandDecision:
    risk: CommandRisk
    allowed_automatically: bool
    reason: str


_BLOCKED = (
    (r"(?i)(curl|wget)\b[^\n|;]{0,300}\|\s*(sudo\s+)?(sh|bash|zsh)\b", "remote content piped directly to a shell"),
    (r"(?i)\brm\s+-[^\n]*r[^\n]*f[^\n]*\s+/(?:\s|$|\*)", "destructive root filesystem deletion"),
    (r"(?i)\b(cat|cp|scp|curl|wget)\b[^\n]*(\.ssh/(id_|authorized_keys)|/etc/shadow)", "sensitive credential/system-file access"),
)
_PRIVILEGED = re.compile(r"(?i)(^|\s)(sudo|su|dnf|apt|yum|pacman|systemctl|firewall-cmd|chown|chmod|mount|umount)\b")
_WRITE = re.compile(r"(?i)(^|\s)(rm|mv|cp|mkdir|touch|tee|sed\s+-i|git\s+(commit|push|reset|checkout)|pip\s+install|pipx\s+install|npm\s+(install|i)|cargo\s+install)\b")
_SAFE = re.compile(r"(?i)^\s*(pwd|ls|cat|head|tail|grep|rg|find|stat|git\s+(status|diff|log|show)|agent-reach\s+doctor)\b")


def evaluate_command(command: str) -> CommandDecision:
    cmd = (command or "").strip()
    for pattern, reason in _BLOCKED:
        if re.search(pattern, cmd):
            return CommandDecision(CommandRisk.BLOCKED, False, reason)
    if _PRIVILEGED.search(cmd):
        return CommandDecision(CommandRisk.PRIVILEGED, False, "privileged or system-changing command requires explicit approval")
    if _WRITE.search(cmd):
        return CommandDecision(CommandRisk.WRITE, False, "filesystem/package/repository write requires policy approval")
    if _SAFE.search(cmd):
        return CommandDecision(CommandRisk.SAFE_READ, True, "recognized read-only diagnostic command")
    return CommandDecision(CommandRisk.WRITE, False, "unknown command defaults to approval-required")
