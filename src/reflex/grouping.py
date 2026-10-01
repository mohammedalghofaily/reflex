"""Groups identical alerts that are close in time, so they only get triaged once."""

from __future__ import annotations

import hashlib
from typing import Iterable

from .alert import Alert, AlertGroup


def group_key(a: Alert) -> tuple:
    return (
        a.source,
        a.rule_id or a.rule_name,
        a.user,
        a.host,
        a.src_ip,
        a.dst_ip,
        a.command_line,
        a.file_name,
    )


def group_alerts(alerts: Iterable[Alert], window_seconds: float) -> list[AlertGroup]:
    """Merges identical alerts that start within `window_seconds` of the first one.

    Groups have a max length, so a long scan doesn't turn into one endless group. It keeps
    making a new group every window, which keeps feeding the risk store. The input doesn't have
    to be sorted, the output is sorted by first_seen.
    """
    ordered = sorted(alerts, key=lambda a: (a.timestamp, a.alert_id))
    open_groups: dict[tuple, list[Alert]] = {}
    done: list[list[Alert]] = []
    for a in ordered:
        k = group_key(a)
        members = open_groups.get(k)
        if members is not None and a.timestamp - members[0].timestamp <= window_seconds:
            members.append(a)
        else:
            if members is not None:
                done.append(members)
            open_groups[k] = [a]
    done.extend(open_groups.values())
    done.sort(key=lambda m: (m[0].timestamp, m[0].alert_id))
    return [
        AlertGroup(
            group_id=hashlib.sha256(f"{m[0].alert_id}|{len(m)}".encode()).hexdigest()[:16],
            representative=m[0],
            members=m,
        )
        for m in done
    ]
