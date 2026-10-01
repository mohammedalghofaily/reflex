"""Builds the only thing that leaves the machine: the pseudonymized alert features I send to Jev."""

from __future__ import annotations

import time
from typing import Any

from .alert import AlertGroup
from .enrich import BaselineStore, GeoResolver, account_type, repetition_features, zone
from .pseudonymize import Pseudonymizer, enforce_allow_list, reduce_command_line, scrub_text


def entity_ids(group: AlertGroup, p: Pseudonymizer) -> tuple[str | None, str | None]:
    a = group.representative
    return p.user(a.user), p.host(a.host)


def build_state(
    group: AlertGroup,
    tactics: list[str],
    p: Pseudonymizer,
    baselines: BaselineStore,
    geo: GeoResolver | None = None,
) -> dict[str, Any]:
    a = group.representative
    user_id, host_id = entity_ids(group, p)
    rule_key = a.rule_id or a.rule_name
    t = time.gmtime(a.timestamp)
    proc = reduce_command_line(a.command_line) if a.command_line else (
        {"exe": a.process.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1], "flags": []} if a.process else None
    )
    alert: dict[str, Any] = {
        "source": a.source,
        "rule": scrub_text(a.rule_name) if a.rule_name else None,
        "severity": None if a.severity is None else round(a.severity, 2),
        "tactics": tactics,
        "time": {"hour_utc": t.tm_hour, "weekday": time.strftime("%A", t)},
        "account_type": account_type(a.user),
        "user_id": user_id,
        "host_id": host_id,
        "src_ip_id": p.ip(a.src_ip),
        "dst_ip_id": p.ip(a.dst_ip),
        "src_zone": zone(a.src_ip, geo),
        "dst_zone": zone(a.dst_ip, geo),
        "repetition": repetition_features(group),
    }
    if proc:
        alert["process"] = proc
    state = {
        "alert": _drop_none(alert),
        "user_baseline": baselines.user_summary(user_id, rule_key),
        "host_baseline": baselines.host_summary(host_id, rule_key),
    }
    return enforce_allow_list(state)


def _drop_none(d: dict) -> dict:
    return {k: (_drop_none(v) if isinstance(v, dict) else v) for k, v in d.items() if v is not None}


def familiarity(group: AlertGroup, p: Pseudonymizer, baselines: BaselineStore) -> tuple[int, int, bool]:
    """(occurrences, how many times this entity fired this rule in training, outside usual hours).

    Worked out locally from the frozen training baselines. The LR baseline and the v2 aggregator
    both use it, so they see exactly the same non-Jev evidence.
    """
    a = group.representative
    u, h = entity_ids(group, p)
    rule = a.rule_id or a.rule_name
    ub = baselines.user_summary(u, rule)
    hb = baselines.host_summary(h, rule)
    seen = max(ub.get("times_this_rule_seen", 0), hb.get("times_this_rule_seen", 0))
    usual = ub.get("usual_hours_utc") or hb.get("usual_hours_utc") or []
    hour = int(a.timestamp // 3600) % 24
    return group.count, seen, bool(usual) and hour not in usual
