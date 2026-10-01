"""The Reflex pipeline.

alerts -> enrich -> group -> [injection guard] -> pseudonymize -> Jev -> aggregate -> route
                                                                          |
                    auto-close <= auto_close_max < local LLM < analyst_min <= analyst
                                                                          |
                                  every alert -> entity risk store -> incidents
                                  every alert -> alert database
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable

from .aggregator import Aggregator
from .alert import Alert, AlertGroup
from .alert_db import AlertDB, Decision
from .config import Config
from .enrich import BaselineStore, GeoResolver, enrich_tactics
from .grouping import group_alerts
from .guards import injection_fields, may_llm_close
from .jev import JevResult, JevUnavailable, Scorer
from .llm import Judge, raw_alert_view
from .outbound import build_state, entity_ids, familiarity
from .pseudonymize import Pseudonymizer
from .risk_store import RiskStore

AUTO_CLOSE, LLM_BENIGN, ANALYST = "auto_close", "llm_benign", "analyst"


@dataclass
class RunStats:
    alerts_in: int = 0
    groups: int = 0
    wall_s: float = 0.0
    jev_wall_s: float = 0.0
    llm_wall_s: float = 0.0
    jev_calls: int = 0
    jev_failures: int = 0
    jev_input_tokens: int = 0
    jev_output_tokens: int = 0
    llm_calls: int = 0
    llm_errors: int = 0
    outbound_payloads: list[dict[str, Any]] = field(default_factory=list)


class Reflex:
    def __init__(
        self,
        cfg: Config,
        pseudonymizer: Pseudonymizer,
        scorer: Scorer,
        judge: Judge,
        aggregator: Aggregator | None = None,
        baselines: BaselineStore | None = None,
        risk_store: RiskStore | None = None,
        alert_db: AlertDB | None = None,
        geo: GeoResolver | None = None,
        use_risk_store: bool = True,
        learn_baselines: bool = False,
        batch_size: int = 256,
    ):
        self.cfg = cfg
        self.p = pseudonymizer
        self.scorer = scorer
        self.judge = judge
        self.agg = aggregator or Aggregator()
        self.baselines = baselines or BaselineStore()
        self.risk = risk_store or RiskStore(cfg.risk)
        self.db = alert_db or AlertDB()
        self.geo = geo
        self.use_risk_store = use_risk_store
        # Baselines come from the training split and stay frozen, like the design says. Turning this
        # on lets alerts closed as benign keep updating them.
        self.learn_baselines = learn_baselines
        self.batch_size = batch_size
        self.stats = RunStats()


    def prepare(self, alerts: Iterable[Alert]) -> list[AlertGroup]:
        alerts = list(alerts)
        for a in alerts:
            a.tactics = enrich_tactics(a)
        self.stats.alerts_in += len(alerts)
        groups = group_alerts(alerts, self.cfg.grouping.window_seconds)
        self.stats.groups += len(groups)
        return groups

    def run(self, alerts: Iterable[Alert]) -> list[Decision]:
        t0 = time.perf_counter()
        groups = self.prepare(alerts)
        out: list[Decision] = []
        for i in range(0, len(groups), self.batch_size):
            batch = groups[i : i + self.batch_size]
            out.extend(self._run_batch(batch))
        self.db.commit()
        self.stats.wall_s += time.perf_counter() - t0
        return out


    def _run_batch(self, batch: list[AlertGroup]) -> list[Decision]:
        # Alerts with injection-looking text never go to any model.
        flagged = {g.group_id: injection_fields(g.representative) for g in batch}
        to_score = [g for g in batch if not flagged[g.group_id]]
        states = [build_state(g, g.representative.tactics, self.p, self.baselines, self.geo) for g in to_score]
        self.stats.outbound_payloads.extend(states)

        t0 = time.perf_counter()
        results = self.scorer.score_many(states) if states else []
        self.stats.jev_wall_s += time.perf_counter() - t0
        jev_by_group: dict[str, JevResult | JevUnavailable] = {
            g.group_id: r for g, r in zip(to_score, results)
        }

        return [self._decide(g, flagged[g.group_id], jev_by_group.get(g.group_id)) for g in batch]

    def _decide(self, g: AlertGroup, injection: list[str], jev: JevResult | JevUnavailable | None) -> Decision:
        a = g.representative
        d = Decision(group_id=g.group_id, timestamp=g.first_seen, route=ANALYST, reason="", tactics=list(a.tactics))
        user_id, host_id = entity_ids(g, self.p)

        if injection:
            d.guard = "instruction_like_text"
            d.reason = f"instruction-like text in {', '.join(injection)}"
        else:
            if isinstance(jev, JevResult):
                self.stats.jev_calls += 0 if jev.cached else 1
                self.stats.jev_input_tokens += jev.input_tokens
                self.stats.jev_output_tokens += jev.output_tokens
                d.jev_scores = jev.scores
                d.jev_latency_s = jev.latency_s
                d.jev_tokens = jev.input_tokens + jev.output_tokens
                fam = familiarity(g, self.p, self.baselines) if self.agg.feature_set == "v2" else None
                d.suspicion = self.agg.suspicion(jev.vector(), a.severity, a.tactics, fam)
            else:
                self.stats.jev_failures += 1
                d.jev_error = str(jev) if jev else "no result"

            r = self.cfg.routing
            if d.suspicion is not None and d.suspicion <= r.auto_close_max:
                d.route, d.reason = AUTO_CLOSE, f"suspicion {d.suspicion:.3f} <= {r.auto_close_max}"
            elif d.suspicion is not None and d.suspicion >= r.analyst_min:
                d.route, d.reason = ANALYST, f"suspicion {d.suspicion:.3f} >= {r.analyst_min}"
            else:
                self._ask_llm(g, d, user_id, host_id)

        # Every alert updates the risk store, no matter where it was routed.
        if self.use_risk_store:
            entities = [(e, t) for e, t in ((user_id, "user"), (host_id, "host")) if e]
            if not entities and a.src_ip:
                entities = [(self.p.ip(a.src_ip), "host")]
            if entities:
                suspicion = d.suspicion if d.suspicion is not None else self.cfg.routing.fallback_suspicion
                outcome = self.risk.update(g.group_id, g.first_seen, suspicion, a.tactics, entities)
                if outcome.action != "none":
                    d.incident_id, d.incident_action, d.priority = outcome.incident_id, outcome.action, outcome.priority

        # Only alerts closed as benign (and not in an incident) teach the baseline what "normal" is.
        if self.learn_baselines and d.route in (AUTO_CLOSE, LLM_BENIGN) and not d.incident_id:
            self.baselines.observe(user_id, host_id, g.first_seen, a.rule_id or a.rule_name, g.count)

        self.db.record(g, d)
        return d

    def _ask_llm(self, g: AlertGroup, d: Decision, user_id, host_id) -> None:
        a = g.representative
        history = self._history(user_id, host_id, g.first_seen)
        view = raw_alert_view(a)
        view["occurrences"] = g.count
        t0 = time.perf_counter()
        v = self.judge.judge(view, history, d.suspicion)
        self.stats.llm_wall_s += time.perf_counter() - t0
        self.stats.llm_calls += 1
        d.llm_verdict, d.llm_reason, d.llm_error, d.llm_latency_s = v.verdict, v.reason, v.error, v.latency_s
        if v.error:
            self.stats.llm_errors += 1
            d.route, d.reason = ANALYST, "local LLM failed; escalated"
        elif v.verdict == "benign" and not may_llm_close(a.tactics):
            d.route, d.guard = ANALYST, "exfil_or_impact"
            d.reason = "LLM may not close exfiltration/impact alerts"
        elif v.verdict == "benign":
            d.route, d.reason = LLM_BENIGN, v.reason
        else:
            d.route, d.reason = ANALYST, v.reason or "LLM: needs_human"

    def _history(self, user_id, host_id, now) -> dict:
        if not self.use_risk_store:
            return {}
        out = {}
        for eid, etype in ((user_id, "user"), (host_id, "host")):
            if not eid:
                continue
            r = self.risk.get(eid, etype, now)   # read-only: not saved
            out[etype] = {
                "risk_score": round(r.risk_score, 3),
                "tactics_seen_recently": sorted(r.tactics_seen),
                "recent_alert_count": len(r.recent_alerts),
                "part_of_open_incident": bool(r.open_incident_id and r.cooldown_until and now < r.cooldown_until),
            }
        return out
