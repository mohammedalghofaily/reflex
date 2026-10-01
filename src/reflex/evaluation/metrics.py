"""Metrics. An attack only counts as caught if it ended up with an analyst or in an incident.

Reaching the LLM isn't enough, because the LLM can close it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from ..alert_db import AlertDB, Decision
from ..risk_store import RiskStore

TARGETS = {
    "benign_auto_resolve_jev": 0.90,
    "per_step_recall": 0.99,
    "per_chain_recall": 1.0,
    "leakage_matches": 0,
}


@dataclass
class Costs:
    """Prices are inputs, not facts. Leave them as None and the report says 'n/a'."""

    jev_usd_per_mtok_in: float | None = None
    jev_usd_per_mtok_out: float | None = None
    gpu_usd_per_hour: float | None = None       # amortized local GPU cost
    cloud_usd_per_mtok_in: float | None = None
    cloud_usd_per_mtok_out: float | None = None


@dataclass
class Report:
    metrics: dict[str, Any] = field(default_factory=dict)
    steps: list[dict[str, Any]] = field(default_factory=list)
    misses: list[dict[str, Any]] = field(default_factory=list)


def evaluate(db: AlertDB, risk: RiskStore | None, *, alerts_in: int | None = None) -> Report:
    decisions = {d.group_id: d for d in db.decisions()}
    in_incident: dict[str, list[str]] = defaultdict(list)
    n_incidents = n_high = 0
    if risk is not None:
        for inc in risk.incidents():
            n_incidents += 1
            n_high += inc.priority == "high"
            for gid in inc.alert_ids:
                in_incident[gid].append(inc.incident_id)

    def caught(gid: str) -> bool:
        d = decisions.get(gid)
        return (d is not None and d.route == "analyst") or gid in in_incident

    members = db.members()
    attack = [m for m in members if m[2] == 1]
    benign = [m for m in members if m[2] == 0]

    # Per-alert
    alert_caught = sum(caught(m[1]) for m in attack)

    # Per-step and per-chain
    steps: dict[tuple, dict] = {}
    for alert_id, gid, _, step, chain, scen in attack:
        k = (scen, chain, step)
        s = steps.setdefault(k, {"scenario": scen, "chain": chain, "step": step, "alerts": 0,
                                 "caught_alerts": 0, "routes": defaultdict(int), "incident": False})
        s["alerts"] += 1
        s["caught_alerts"] += caught(gid)
        d = decisions.get(gid)
        s["routes"][d.route if d else "missing"] += 1
        s["incident"] |= gid in in_incident
    step_rows = []
    for s in steps.values():
        s["caught"] = s["caught_alerts"] > 0
        s["routes"] = dict(s["routes"])
        s["caught_by"] = (
            "analyst" if s["routes"].get("analyst") else "incident" if s["incident"] else "-"
        )
        step_rows.append(s)
    chains: dict[tuple, bool] = defaultdict(bool)
    for s in step_rows:
        chains[(s["scenario"], s["chain"])] |= s["caught"]

    # Benign
    def route_of(gid):
        d = decisions.get(gid)
        return d.route if d else None

    benign_jev_closed = sum(route_of(m[1]) == "auto_close" and m[1] not in in_incident for m in benign)
    benign_closed = sum(route_of(m[1]) in ("auto_close", "llm_benign") and m[1] not in in_incident for m in benign)

    # Routes over groups (units of work)
    groups = list(decisions.values())
    n = len(groups) or 1
    to_llm = sum(d.llm_verdict is not None or d.llm_error is not None for d in groups)
    route_counts = defaultdict(int)
    for d in groups:
        route_counts[d.route] += 1

    span_days = _span_days(groups)
    analyst_items = route_counts["analyst"] + n_incidents

    m = {
        "alerts": len(members) if alerts_in is None else alerts_in,
        "groups": len(groups),
        "grouping_reduction": round(1 - len(groups) / max(len(members), 1), 4),
        "attack_alerts": len(attack),
        "benign_alerts": len(benign),
        "benign_auto_resolve_jev": _ratio(benign_jev_closed, len(benign)),
        "benign_closed_total": _ratio(benign_closed, len(benign)),
        "per_step_recall": _ratio(sum(s["caught"] for s in step_rows), len(step_rows)),
        "per_alert_recall": _ratio(alert_caught, len(attack)),
        "per_chain_recall": _ratio(sum(chains.values()), len(chains)),
        "attack_steps": len(step_rows),
        "attack_chains": len(chains),
        "route_share": {
            "auto_close": round(route_counts["auto_close"] / n, 4),
            "sent_to_llm": round(to_llm / n, 4),
            "llm_benign": round(route_counts["llm_benign"] / n, 4),
            "analyst": round(route_counts["analyst"] / n, 4),
        },
        "guards": {
            "instruction_like_text": sum(d.guard == "instruction_like_text" for d in groups),
            "exfil_or_impact": sum(d.guard == "exfil_or_impact" for d in groups),
        },
        "incidents": n_incidents,
        "high_priority_incidents": n_high,
        "analyst_items": analyst_items,
        "analyst_items_per_day": round(analyst_items / span_days, 1) if span_days else None,
    }
    misses = [
        {"scenario": s["scenario"], "chain": s["chain"], "step": s["step"], "alerts": s["alerts"],
         "routes": s["routes"], "why": _why_missed(s, decisions, db)}
        for s in step_rows if not s["caught"]
    ]
    return Report(m, sorted(step_rows, key=lambda s: (s["scenario"] or "", s["chain"] or "", s["step"] or "")), misses)


def _why_missed(step: dict, decisions: dict[str, Decision], db: AlertDB) -> str:
    gids = {gid for _, gid, a, st, ch, sc in db.members()
            if a == 1 and st == step["step"] and ch == step["chain"] and sc == step["scenario"]}
    reasons = defaultdict(int)
    for gid in gids:
        d = decisions.get(gid)
        if d is None:
            continue
        if d.route == "auto_close":
            reasons[f"auto-closed (suspicion {d.suspicion:.2f})"] += 1
        elif d.route == "llm_benign":
            reasons[f"LLM closed: {d.llm_reason}"] += 1
    top = sorted(reasons.items(), key=lambda kv: -kv[1])[:3]
    return "; ".join(f"{r} x{n}" for r, n in top) + "; never reached an incident"


def cost_and_time(stats, costs: Costs, alerts: int) -> dict[str, Any]:
    per_k = 1000.0 / max(alerts, 1)
    out: dict[str, Any] = {
        "wall_seconds_per_1k_alerts": round(stats.wall_s * per_k, 3),
        "jev_seconds_per_1k_alerts": round(stats.jev_wall_s * per_k, 3),
        "llm_seconds_per_1k_alerts": round(stats.llm_wall_s * per_k, 3),
        "jev_calls": stats.jev_calls,
        "jev_failures": stats.jev_failures,
        "llm_calls": stats.llm_calls,
        "llm_errors": stats.llm_errors,
    }
    usd = 0.0
    known = True
    if stats.jev_input_tokens or stats.jev_output_tokens:
        if costs.jev_usd_per_mtok_in is None or costs.jev_usd_per_mtok_out is None:
            known = False
        else:
            usd += stats.jev_input_tokens / 1e6 * costs.jev_usd_per_mtok_in
            usd += stats.jev_output_tokens / 1e6 * costs.jev_usd_per_mtok_out
    if stats.llm_wall_s:
        if costs.gpu_usd_per_hour is None:
            known = False
        else:
            usd += stats.llm_wall_s / 3600 * costs.gpu_usd_per_hour
    out["usd_per_1k_alerts"] = round(usd * per_k, 5) if known else "n/a (set prices)"
    return out


def _ratio(a, b):
    return round(a / b, 4) if b else None


def _span_days(groups: list[Decision]) -> float:
    if not groups:
        return 0.0
    ts = [d.timestamp for d in groups]
    return max((max(ts) - min(ts)) / 86400, 1 / 24)
