"""The pseudonymizer. It's the only door between the raw alerts and anything that leaves the machine.

The rules from my design:
  1. Usernames, hostnames and IPs -> HMAC-SHA256, cut to 16 hex characters.
  2. Values get normalized first (lowercase, domain suffixes removed).
  3. Command lines become the executable name + flags. Everything else is dropped.
  4. Allow-list of fields. Anything not on the list is blocked.
"""

from __future__ import annotations

import hashlib
import hmac as _stdlib_hmac
import ipaddress
import ntpath
import posixpath
import re
from typing import Any

BLOCK_SIZE = 64  # SHA-256 block size in bytes
IPAD = 0x36
OPAD = 0x5C


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    """HMAC(K, m) = H((K xor opad) || H((K xor ipad) || m)), written out step by step.

    Gives the same result as hmac.new(key, message, sha256).digest(). The tests check that.
    """
    # 1. Make the key 64 bytes: hash it if it's too long, then pad it with zeros.
    if len(key) > BLOCK_SIZE:
        key = hashlib.sha256(key).digest()
    key = key.ljust(BLOCK_SIZE, b"\x00")
    # 2. Make two versions of the key.
    inner_key = bytes(b ^ IPAD for b in key)
    outer_key = bytes(b ^ OPAD for b in key)
    # 3. Inner hash.
    inner = hashlib.sha256(inner_key + message).digest()
    # 4. Outer hash. It seals the inner one, which is what blocks length extension.
    return hashlib.sha256(outer_key + inner).digest()


def normalize_user(user: str) -> str:
    u = user.strip().lower()
    if "\\" in u:                 # DOMAIN\user
        u = u.split("\\", 1)[1]
    if "@" in u:                  # user@domain.tld
        u = u.split("@", 1)[0]
    return u


def normalize_host(host: str) -> str:
    h = host.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(h)
        return h
    except ValueError:
        return h.split(".", 1)[0]   # strip domain suffix


def normalize_ip(ip: str) -> str:
    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError:
        return ip.strip().lower()


_FLAG_RE = re.compile(r"^(--?[A-Za-z?][\w?-]*|/[A-Za-z?][\w?:]*)$")


def reduce_command_line(cmd: str) -> dict[str, Any]:
    """Keeps the executable's name and its flags. Arguments, paths and payloads get dropped."""
    tokens = _split_command_line(cmd)
    if not tokens:
        return {"exe": None, "flags": []}
    exe_path = tokens[0]
    exe = ntpath.basename(exe_path) if "\\" in exe_path else posixpath.basename(exe_path)
    flags: list[str] = []
    for tok in tokens[1:]:
        name = tok.split("=", 1)[0]
        # Windows flags like /all have no second slash, Linux paths do.
        if name.startswith("/") and name.count("/") > 1:
            continue
        if name.startswith("/") and ":" in name:
            name = name.split(":", 1)[0]
        if _FLAG_RE.match(name) and len(name) <= 32 and name not in flags:
            flags.append(name)
    return {"exe": exe.lower() or None, "flags": flags}


def _split_command_line(cmd: str) -> list[str]:
    out, cur, quote = [], [], None
    for ch in cmd.strip():
        if quote:
            if ch == quote:
                quote = None
            else:
                cur.append(ch)
        elif ch in "\"'":
            quote = ch
        elif ch.isspace():
            if cur:
                out.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        out.append("".join(cur))
    return out


_IP_IN_TEXT = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"                    # IPv4
    r"|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"  # full IPv6
    r"|\b[0-9a-fA-F:]*::[0-9a-fA-F:]*[0-9a-fA-F]\b"   # compressed IPv6
)


def scrub_text(text: str) -> str:
    """Rule names come from the detection rules, but some sensors paste IPs into them. This removes those."""
    return _IP_IN_TEXT.sub("<ip>", text)


class Pseudonymizer:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("HMAC key must not be empty")
        self._key = key

    def token(self, normalized_value: str) -> str:
        return hmac_sha256(self._key, normalized_value.encode()).hex()[:16]

    def user(self, value: str | None) -> str | None:
        return self.token("user:" + normalize_user(value)) if value else None

    def host(self, value: str | None) -> str | None:
        return self.token("host:" + normalize_host(value)) if value else None

    def ip(self, value: str | None) -> str | None:
        return self.token("ip:" + normalize_ip(value)) if value else None


def verify_against_stdlib(key: bytes, message: bytes) -> bool:
    return _stdlib_hmac.compare_digest(
        hmac_sha256(key, message), _stdlib_hmac.new(key, message, hashlib.sha256).digest()
    )


# Allow-list. The payload I send out is built from these paths only.

ALLOWED_OUTBOUND_FIELDS: frozenset[str] = frozenset(
    {
        "alert.source",
        "alert.rule",
        "alert.severity",
        "alert.tactics",
        "alert.time.hour_utc",
        "alert.time.weekday",
        "alert.process.exe",
        "alert.process.flags",
        "alert.account_type",
        "alert.user_id",
        "alert.host_id",
        "alert.src_ip_id",
        "alert.dst_ip_id",
        "alert.src_zone",
        "alert.dst_zone",
        "alert.repetition.occurrences",
        "alert.repetition.span_minutes",
        "alert.repetition.median_interval_seconds",
        "alert.repetition.interval_regularity",
        "user_baseline.known",
        "user_baseline.usual_hours_utc",
        "user_baseline.alerts_seen",
        "user_baseline.times_this_rule_seen",
        "user_baseline.distinct_rules_seen",
        "user_baseline.days_observed",
        "host_baseline.known",
        "host_baseline.usual_hours_utc",
        "host_baseline.alerts_seen",
        "host_baseline.times_this_rule_seen",
        "host_baseline.distinct_rules_seen",
        "host_baseline.days_observed",
    }
)


class BlockedFieldError(ValueError):
    pass


def enforce_allow_list(payload: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Returns a copy of the payload with only the allow-listed fields.

    Anything unknown gets dropped, never forwarded. Raises if nothing is left.
    """
    out: dict[str, Any] = {}
    for k, v in payload.items():
        path = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            sub = enforce_allow_list(v, path) if any(
                f.startswith(path + ".") for f in ALLOWED_OUTBOUND_FIELDS
            ) else {}
            if sub:
                out[k] = sub
        elif path in ALLOWED_OUTBOUND_FIELDS:
            out[k] = v
    if not prefix and not out:
        raise BlockedFieldError("payload had no allow-listed fields")
    return out
