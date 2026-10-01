"""All the settings. The thresholds here are just starting values, I tune them on santos."""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

HOUR = 3600.0


@dataclass
class RoutingConfig:
    auto_close_max: float = 0.15   # suspicion <= this -> auto-close
    analyst_min: float = 0.85      # suspicion >= this -> analyst queue
    # What the risk store records when Jev is down and there's no score.
    fallback_suspicion: float = 0.5


@dataclass
class RiskConfig:
    half_life_hours: float = 24.0
    window_hours: float = 72.0      # tactics / recent alerts older than this are dropped
    cooldown_hours: float = 6.0
    risk_threshold: float = 1.5
    # Anything at or below the floor counts as noise: no risk, no tactics, and it can't
    # open or join an incident. 0.0 = my original design.
    suspicion_floor: float = 0.0
    min_tactics_for_incident: int = 2
    high_priority_tactics: int = 3
    high_priority_tactic_names: tuple[str, ...] = ("exfiltration", "impact")


@dataclass
class GroupingConfig:
    # Identical alerts inside this window become one group.
    window_seconds: float = 3600.0


@dataclass
class LLMConfig:
    base_url: str = "http://localhost:11434"
    model: str = "qwen3:8b"
    timeout_seconds: float = 30.0
    temperature: float = 0.0
    max_history_alerts: int = 10
    prompt: str = "v1"                      # "v1" is the original prompt, "v2" is the few-shot one built from training data
    examples_path: str | None = None        # few-shot examples, taken from training scenarios only


@dataclass
class JevConfig:
    model: str = "jev-latest"
    timeout_seconds: float = 5.0
    max_retries: int = 1
    concurrency: int = 16


@dataclass
class Config:
    routing: RoutingConfig = field(default_factory=RoutingConfig)
    risk: RiskConfig = field(default_factory=RiskConfig)
    grouping: GroupingConfig = field(default_factory=GroupingConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    jev: JevConfig = field(default_factory=JevConfig)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Config":
        risk = dict(d.get("risk", {}))
        if "high_priority_tactic_names" in risk:
            risk["high_priority_tactic_names"] = tuple(risk["high_priority_tactic_names"])
        return cls(
            routing=RoutingConfig(**d.get("routing", {})),
            risk=RiskConfig(**risk),
            grouping=GroupingConfig(**d.get("grouping", {})),
            llm=LLMConfig(**d.get("llm", {})),
            jev=JevConfig(**d.get("jev", {})),
        )

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        if path is None or not Path(path).exists():
            return cls()
        return cls.from_dict(json.loads(Path(path).read_text()))


def hmac_key_from_env() -> bytes:
    """Gets the HMAC key. It never leaves the machine and never gets logged."""
    key = os.environ.get("REFLEX_HMAC_KEY")
    if not key:
        raise RuntimeError(
            "REFLEX_HMAC_KEY is not set. Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    return key.encode()
