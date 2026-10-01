"""Alert database. Every decision and the reason for it gets saved here for the evaluation."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass, field

from .alert import AlertGroup


@dataclass
class Decision:
    group_id: str
    timestamp: float
    route: str                      # auto_close | llm_benign | analyst
    reason: str
    suspicion: float | None = None
    jev_scores: dict[str, float] | None = None
    jev_error: str | None = None
    llm_verdict: str | None = None
    llm_reason: str | None = None
    llm_error: str | None = None
    guard: str | None = None        # set when one of the non-LLM rules forced the route
    tactics: list[str] = field(default_factory=list)
    incident_id: str | None = None
    incident_action: str | None = None
    priority: str | None = None
    jev_latency_s: float = 0.0
    llm_latency_s: float = 0.0
    jev_tokens: int = 0


class AlertDB:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS decisions (group_id TEXT PRIMARY KEY, ts REAL, route TEXT, body TEXT);
            CREATE TABLE IF NOT EXISTS members (
                alert_id TEXT PRIMARY KEY, group_id TEXT, is_attack INTEGER,
                step TEXT, chain TEXT, scenario TEXT);
            """
        )

    def record(self, group: AlertGroup, d: Decision) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO decisions VALUES (?,?,?,?)",
            (d.group_id, d.timestamp, d.route, json.dumps(asdict(d))),
        )
        self.db.executemany(
            "INSERT OR REPLACE INTO members VALUES (?,?,?,?,?,?)",
            [
                (
                    m.alert_id, group.group_id,
                    None if m.label is None else int(m.label.is_attack),
                    m.label.step if m.label else None,
                    m.label.chain if m.label else None,
                    m.label.scenario if m.label else None,
                )
                for m in group.members
            ],
        )

    def commit(self) -> None:
        self.db.commit()

    def decisions(self) -> list[Decision]:
        return [Decision(**json.loads(b)) for (b,) in self.db.execute("SELECT body FROM decisions ORDER BY ts")]

    def members(self) -> list[tuple]:
        return list(self.db.execute("SELECT alert_id, group_id, is_attack, step, chain, scenario FROM members"))
