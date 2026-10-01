"""Leakage scan. Searches every payload I send out for the original usernames, hostnames, IPs
and command lines.

The goal is 0 matches.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .alert import Alert
from .pseudonymize import normalize_host, normalize_user

_TOKEN_RE = re.compile(r"[A-Za-z0-9_.$@\\-]+")
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b|[0-9a-fA-F]*:[0-9a-fA-F:]{2,}")
MIN_LEN = 3   # shorter identifiers ("a", "pc") would match by chance


@dataclass
class LeakReport:
    payloads_scanned: int = 0
    matches: list[dict[str, Any]] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.matches


class LeakageScanner:
    def __init__(self, alerts: Iterable[Alert]):
        self.users: set[str] = set()
        self.hosts: set[str] = set()
        self.ips: set[str] = set()
        self.cmdlines: set[str] = set()
        for a in alerts:
            if a.user and len(a.user) >= MIN_LEN:
                self.users |= {a.user.lower(), normalize_user(a.user)}
            if a.host and len(a.host) >= MIN_LEN:
                self.hosts |= {a.host.lower(), normalize_host(a.host)}
            for ip in (a.src_ip, a.dst_ip):
                if ip:
                    self.ips.add(ip.lower())
            if a.command_line and len(a.command_line.split()) > 1:
                self.cmdlines.add(a.command_line.strip())
        self.users = {u for u in self.users if len(u) >= MIN_LEN}
        self.hosts = {h for h in self.hosts if len(h) >= MIN_LEN}

    def scan(self, payloads: Iterable[dict[str, Any]]) -> LeakReport:
        rep = LeakReport()
        for i, p in enumerate(payloads):
            rep.payloads_scanned += 1
            text = json.dumps(p, ensure_ascii=False)
            low = text.lower()
            tokens = set(_TOKEN_RE.findall(low))
            for kind, pool in (("user", self.users), ("host", self.hosts)):
                for hit in tokens & pool:
                    rep.matches.append({"payload": i, "kind": kind, "value": hit})
            for ip in set(_IP_RE.findall(low)) & self.ips:
                rep.matches.append({"payload": i, "kind": "ip", "value": ip})
            for s in _strings(p):
                if s.strip() in self.cmdlines:
                    rep.matches.append({"payload": i, "kind": "command_line", "value": s})
        return rep


def _strings(obj):
    if isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)
    elif isinstance(obj, str):
        yield obj
