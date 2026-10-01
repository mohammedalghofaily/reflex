"""One alert format for every sensor. If a field is empty it stays None, I never guess it."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The 14 ATT&CK Enterprise tactics. Don't reorder them, the one-hot features depend on this order.
TACTICS: tuple[str, ...] = (
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
)


@dataclass
class Label:
    """The ground truth. Only the evaluation reads this, the triage pipeline never sees it."""

    is_attack: bool
    step: str | None = None      # attack step (AIT-ADS time_label), e.g. "dirb", "webshell"
    chain: str | None = None     # which attack chain the step belongs to
    scenario: str | None = None


@dataclass
class Alert:
    alert_id: str
    timestamp: float                 # epoch seconds, UTC
    source: str                      # wazuh | suricata | aminer | sigma | ...
    rule_id: str | None = None
    rule_name: str | None = None
    severity: float | None = None    # normalized to 0..1
    tactics: list[str] = field(default_factory=list)
    user: str | None = None
    host: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    command_line: str | None = None
    process: str | None = None
    file_name: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    label: Label | None = None

    def string_fields(self) -> dict[str, str]:
        """Every text field an attacker could control. The injection guard checks these."""
        out = {}
        for name in ("rule_name", "user", "host", "command_line", "process", "file_name"):
            v = getattr(self, name)
            if isinstance(v, str) and v:
                out[name] = v
        return out


@dataclass
class AlertGroup:
    """Identical alerts merged together so they only get triaged once."""

    group_id: str
    representative: Alert
    members: list[Alert]

    @property
    def first_seen(self) -> float:
        return self.members[0].timestamp

    @property
    def last_seen(self) -> float:
        return self.members[-1].timestamp

    @property
    def count(self) -> int:
        return len(self.members)

    @property
    def is_attack(self) -> bool | None:
        labels = [m.label for m in self.members if m.label is not None]
        if not labels:
            return None
        return any(l.is_attack for l in labels)

    def intervals(self) -> list[float]:
        ts = [m.timestamp for m in self.members]
        return [b - a for a, b in zip(ts, ts[1:])]
