"""Entity risk store. Jev looks at one alert at a time, so this is the memory that connects them.
Attacks happen in stages and each stage on its own can look harmless.

    risk_new = risk_old * 2^(-dt / half_life) + max(0, suspicion - floor)

My original design didn't have the floor. On the real data, busy servers send hundreds of
tiny alerts a day and they added up past the threshold on their own, so everything became
an incident. The floor fixes that. Floor 0 = the original formula.

Decay is calculated when a record is read or updated, so I don't need a background job.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field

from .config import HOUR, RiskConfig


@dataclass
class EntityRecord:
    entity_id: str
    entity_type: str                         # "user" | "host"
    risk_score: float = 0.0
    last_updated: float | None = None
    tactics_seen: dict[str, float] = field(default_factory=dict)       # tactic -> last seen ts
    recent_alerts: list[tuple[str, float]] = field(default_factory=list)  # (group_id, ts)
    cooldown_until: float | None = None
    open_incident_id: str | None = None


@dataclass
class Incident:
    incident_id: str
    created: float
    priority: str                            # "normal" | "high"
    entities: set[str] = field(default_factory=set)
    alert_ids: set[str] = field(default_factory=set)
    tactics: set[str] = field(default_factory=set)


@dataclass
class RiskOutcome:
    action: str                              # none | incident_created | attached
    incident_id: str | None = None
    priority: str | None = None
    risk_after: dict[str, float] = field(default_factory=dict)
    tactics_after: dict[str, list[str]] = field(default_factory=dict)


def decayed(risk: float, last: float | None, now: float, half_life_hours: float) -> float:
    if last is None:
        return risk
    dt = max(0.0, now - last)
    return risk * 2 ** (-dt / (half_life_hours * HOUR))


class RiskStore:
    def __init__(self, cfg: RiskConfig, path: str = ":memory:"):
        self.cfg = cfg
        self.db = sqlite3.connect(path)
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS entities (
                entity_id TEXT PRIMARY KEY, entity_type TEXT, risk_score REAL, last_updated REAL,
                tactics_seen TEXT, recent_alerts TEXT, cooldown_until REAL, open_incident_id TEXT);
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY, created REAL, priority TEXT,
                entities TEXT, alert_ids TEXT, tactics TEXT);
            """
        )

    # Saving and loading

    def _load(self, entity_id: str, entity_type: str) -> EntityRecord:
        row = self.db.execute("SELECT * FROM entities WHERE entity_id=?", (entity_id,)).fetchone()
        if not row:
            return EntityRecord(entity_id, entity_type)
        return EntityRecord(
            row[0], row[1], row[2], row[3], json.loads(row[4]),
            [tuple(x) for x in json.loads(row[5])], row[6], row[7],
        )

    def _save(self, r: EntityRecord) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO entities VALUES (?,?,?,?,?,?,?,?)",
            (r.entity_id, r.entity_type, r.risk_score, r.last_updated, json.dumps(r.tactics_seen),
             json.dumps(r.recent_alerts), r.cooldown_until, r.open_incident_id),
        )

    def incident(self, incident_id: str) -> Incident | None:
        row = self.db.execute("SELECT * FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        if not row:
            return None
        return Incident(row[0], row[1], row[2], set(json.loads(row[3])), set(json.loads(row[4])), set(json.loads(row[5])))

    def incidents(self) -> list[Incident]:
        ids = [r[0] for r in self.db.execute("SELECT incident_id FROM incidents ORDER BY created")]
        return [self.incident(i) for i in ids]

    def _save_incident(self, inc: Incident) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?)",
            (inc.incident_id, inc.created, inc.priority, json.dumps(sorted(inc.entities)),
             json.dumps(sorted(inc.alert_ids)), json.dumps(sorted(inc.tactics))),
        )

    def get(self, entity_id: str, entity_type: str, now: float) -> EntityRecord:
        """Reads a record with the decay and the window already applied as of `now`."""
        r = self._load(entity_id, entity_type)
        self._age(r, now)
        return r

    # Updating

    def _age(self, r: EntityRecord, now: float) -> None:
        r.risk_score = decayed(r.risk_score, r.last_updated, now, self.cfg.half_life_hours)
        r.last_updated = now if r.last_updated is None else max(r.last_updated, now)
        horizon = now - self.cfg.window_hours * HOUR
        r.tactics_seen = {t: ts for t, ts in r.tactics_seen.items() if ts >= horizon}
        r.recent_alerts = [(a, ts) for a, ts in r.recent_alerts if ts >= horizon]

    def _is_high(self, tactics: set[str]) -> bool:
        return len(tactics) >= self.cfg.high_priority_tactics or bool(
            tactics & set(self.cfg.high_priority_tactic_names)
        )

    def update(
        self,
        group_id: str,
        now: float,
        suspicion: float,
        tactics: list[str],
        entities: list[tuple[str, str]],   # [(entity_id, "user"|"host"), ...]
    ) -> RiskOutcome:
        """Every alert goes through here, no matter how it was routed."""
        out = RiskOutcome(action="none")
        records = []
        signal = max(0.0, suspicion - self.cfg.suspicion_floor)
        above = suspicion > self.cfg.suspicion_floor
        for eid, etype in entities:
            r = self.get(eid, etype, now)
            r.risk_score += signal
            if above:
                for t in tactics:
                    r.tactics_seen[t] = now
            if above:
                r.recent_alerts.append((group_id, now))
            records.append(r)

        for r in records:
            in_cooldown = r.cooldown_until is not None and now < r.cooldown_until and r.open_incident_id
            if not above:
                # Below the floor = noise. It can't open or join an incident, even during a cooldown,
                # otherwise busy servers drag everything in.
                continue
            if in_cooldown:
                inc = self.incident(r.open_incident_id)
                inc.alert_ids.add(group_id)
                inc.entities.add(r.entity_id)
                inc.tactics |= set(r.tactics_seen)
                if self._is_high(inc.tactics):
                    inc.priority = "high"
                self._save_incident(inc)
                out = _merge(out, "attached", inc)
                continue
            triggered = (
                r.risk_score >= self.cfg.risk_threshold
                or len(r.tactics_seen) >= self.cfg.min_tactics_for_incident
            )
            if triggered:
                inc = self._reuse_incident_for(records, now) or Incident(
                    incident_id=uuid.uuid4().hex[:12], created=now, priority="normal"
                )
                inc.entities.add(r.entity_id)
                inc.alert_ids |= {a for a, _ in r.recent_alerts}
                inc.tactics |= set(r.tactics_seen)
                inc.priority = "high" if self._is_high(inc.tactics) else inc.priority
                r.open_incident_id = inc.incident_id
                r.cooldown_until = now + self.cfg.cooldown_hours * HOUR
                self._save_incident(inc)
                out = _merge(out, "incident_created", inc)

        for r in records:
            out.risk_after[r.entity_id] = round(r.risk_score, 6)
            out.tactics_after[r.entity_id] = sorted(r.tactics_seen)
            self._save(r)
        self.db.commit()
        return out

    def _reuse_incident_for(self, records: list[EntityRecord], now: float) -> Incident | None:
        """If the user or host on this alert already has an open incident, use that one."""
        for r in records:
            if r.open_incident_id and r.cooldown_until and now < r.cooldown_until:
                return self.incident(r.open_incident_id)
        return None


def _merge(out: RiskOutcome, action: str, inc: Incident) -> RiskOutcome:
    rank = {"none": 0, "attached": 1, "incident_created": 2}
    if rank[action] >= rank[out.action]:
        out.action = action
        out.incident_id = inc.incident_id
    out.priority = "high" if inc.priority == "high" or out.priority == "high" else inc.priority
    return out
