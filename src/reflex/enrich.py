"""Enrichment: ATT&CK tactics, user and host baselines, and the network zone ("geo") lookup."""

from __future__ import annotations

import ipaddress
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable

from .alert import TACTICS, Alert, AlertGroup

# Tactics

_TACTIC_ALIASES = {t.replace("_", " "): t for t in TACTICS} | {
    "command and control": "command_and_control",
    "c2": "command_and_control",
}

# Keyword -> tactic, for sensors that don't tag ATT&CK themselves (Suricata, AMiner, some
# Wazuh rules). One alert can match several patterns.
KEYWORD_TACTICS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(port ?scan|nmap|network scan|scan(ning)? detected|ET SCAN)\w*", re.I), "reconnaissance"),
    (re.compile(r"\b(wpscan|dirb|gobuster|nikto|directory (brute|enumeration)|web ?scan)\w*", re.I), "reconnaissance"),
    (re.compile(r"\b(web ?shell|webshell|code injection|sql injection|ET WEB_SERVER|exploit)\w*", re.I), "initial_access"),
    (re.compile(r"\b(reverse shell|cmd\.exe|powershell|bash -i|bin/sh)\w*", re.I), "execution"),
    (re.compile(r"\b(cron|systemd service|new service|service creat|scheduled task|autorun)\w*", re.I), "persistence"),
    (re.compile(r"\b(sudo|privilege|setuid|root access|escalat)\w*", re.I), "privilege_escalation"),
    (re.compile(r"\b(log(s)? (clear|delet)|audit(d)? stop|disable (defender|firewall))\w*", re.I), "defense_evasion"),
    (re.compile(r"\b(brute ?force|password (crack|guess|spray)|authentication fail|lsass|credential|hashcat|john)\w*", re.I), "credential_access"),
    (re.compile(r"\b(whoami|net user|systeminfo|discovery|enumerat)\w*", re.I), "discovery"),
    (re.compile(r"\b(lateral|psexec|remote service|wmic /node|smb exec|ssh from internal)\w*", re.I), "lateral_movement"),
    (re.compile(r"\b(beacon|c2|command and control|dns tunnel|ET TROJAN|ET MALWARE)\w*", re.I), "command_and_control"),
    (re.compile(r"\b(exfil|dnsteal|data transfer to external|large outbound|dns (exfil|tunnel))\w*", re.I), "exfiltration"),
    (re.compile(r"\b(service stop(ped)?|ransom|wipe|encrypt(ed)? files|shutdown|defac)\w*", re.I), "impact"),
]


def normalize_tactic(name: str) -> str | None:
    key = name.strip().lower().replace("-", " ").replace("_", " ")
    return _TACTIC_ALIASES.get(key)


def enrich_tactics(alert: Alert) -> list[str]:
    """Keeps the tactics the sensor gave and adds keyword matches from the rule name and process."""
    found = [t for t in (normalize_tactic(x) for x in alert.tactics) if t]
    text = " ".join(filter(None, [alert.rule_name, alert.process, alert.command_line]))
    for pat, tactic in KEYWORD_TACTICS:
        if tactic not in found and pat.search(text):
            found.append(tactic)
    return found


# Account type. Worked out locally from the real name, only the category gets sent out.

_SERVICE_RE = re.compile(r"^(svc[_-]|service|www-data|apache|nginx|mysql|postgres|daemon|nobody|systemd-|_)|(\$$)")
_ADMIN_RE = re.compile(r"^(root|admin|administrator|adm[_-])|(admin$)|(-adm$)")


def account_type(user: str | None) -> str:
    if not user:
        return "unknown"
    u = user.strip().lower().split("\\")[-1].split("@")[0]
    if u.endswith("$"):
        return "machine"
    if _ADMIN_RE.search(u):
        return "admin"
    if _SERVICE_RE.search(u):
        return "service"
    return "user"


# Zone ("geo") lookup. Private ranges are internal. An optional resolver can map public
# IPs to a country, which is vague enough to send out.

GeoResolver = Callable[[str], str | None]


def zone(ip: str | None, geo: GeoResolver | None = None) -> str | None:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if addr.is_loopback:
        return "loopback"
    if addr.is_private or addr.is_link_local:
        return "internal"
    if geo:
        country = geo(ip)
        if country:
            return f"external:{country}"
    return "external"


# Baselines per user and host (keyed by pseudonym)


@dataclass
class EntityBaseline:
    hour_counts: list[int] = field(default_factory=lambda: [0] * 24)
    rule_counts: Counter = field(default_factory=Counter)
    total: int = 0
    first_seen: float | None = None
    last_seen: float | None = None

    def observe(self, ts: float, rule: str | None, n: int = 1) -> None:
        self.hour_counts[int(ts // 3600) % 24] += n
        if rule:
            self.rule_counts[rule] += n
        self.total += n
        self.first_seen = ts if self.first_seen is None else min(self.first_seen, ts)
        self.last_seen = ts if self.last_seen is None else max(self.last_seen, ts)

    def usual_hours(self, min_share: float = 0.03) -> list[int]:
        if not self.total:
            return []
        return [h for h, c in enumerate(self.hour_counts) if c / self.total >= min_share]

    def summary(self, rule: str | None) -> dict:
        if not self.total:
            return {"known": False}
        days = ((self.last_seen or 0) - (self.first_seen or 0)) / 86400
        return {
            "known": True,
            "usual_hours_utc": self.usual_hours(),
            "alerts_seen": self.total,
            "times_this_rule_seen": self.rule_counts.get(rule, 0) if rule else 0,
            "distinct_rules_seen": len(self.rule_counts),
            "days_observed": round(days, 1),
        }


class BaselineStore:
    """Normal activity per user and per host.

    Built from the training split and then frozen, like my design says. Reflex can also keep
    learning from alerts closed as benign (learn_baselines), but that's off by default so attack
    traffic never becomes "normal".
    """

    def __init__(self) -> None:
        self.users: dict[str, EntityBaseline] = defaultdict(EntityBaseline)
        self.hosts: dict[str, EntityBaseline] = defaultdict(EntityBaseline)

    def observe(self, user_id: str | None, host_id: str | None, ts: float, rule: str | None, n: int = 1) -> None:
        if user_id:
            self.users[user_id].observe(ts, rule, n)
        if host_id:
            self.hosts[host_id].observe(ts, rule, n)

    def user_summary(self, user_id: str | None, rule: str | None) -> dict:
        if not user_id or user_id not in self.users:
            return {"known": False}
        return self.users[user_id].summary(rule)

    def host_summary(self, host_id: str | None, rule: str | None) -> dict:
        if not host_id or host_id not in self.hosts:
            return {"known": False}
        return self.hosts[host_id].summary(rule)


def repetition_features(group: AlertGroup) -> dict:
    """How the duplicates of this alert were spaced out. Very regular spacing points to beaconing or cron."""
    iv = group.intervals()
    out = {
        "occurrences": group.count,
        "span_minutes": round((group.last_seen - group.first_seen) / 60, 1),
    }
    if len(iv) >= 2:
        med = statistics.median(iv)
        mean = statistics.fmean(iv)
        cv = statistics.pstdev(iv) / mean if mean > 0 else 0.0
        out["median_interval_seconds"] = round(med, 1)
        # 1.0 = perfectly regular, 0.0 = irregular
        out["interval_regularity"] = round(max(0.0, 1.0 - min(cv, 1.0)), 2)
    elif iv:
        out["median_interval_seconds"] = round(iv[0], 1)
    return out
