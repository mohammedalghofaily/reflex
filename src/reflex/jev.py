"""Jev scoring. Four Score questions about the pseudonymized alert, all in one request.

Each question has three levels, so Jev scores it 0 to 2. I divide by 2 to get 0 to 1 before
the aggregator combines them.
"""

from __future__ import annotations

import asyncio
import sys
import hashlib
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .config import JevConfig

QUESTION_IDS = ("off_hours", "unusual_activity", "account_mismatch", "malicious_automation")


def _questions():
    from typesafe_sdk import Score

    return {
        "off_hours": Score(
            instructions=(
                "Did the activity in `alert` happen outside the user's normal working hours? "
                "Compare `alert.time.hour_utc` with `user_baseline.usual_hours_utc`. If the user "
                "baseline is not known, use `host_baseline` instead."
            ),
            criteria=[
                "Inside the hours this user or host is usually active",
                "At the edge of the usual hours, or there is too little history to tell",
                "Clearly outside the hours this user or host is usually active",
            ],
        ),
        "unusual_activity": Score(
            instructions=(
                "Is this alert inconsistent with the user's and host's usual activity? Consider how "
                "often this rule has fired for them before (`times_this_rule_seen`), how much history "
                "exists, and the process and network zones involved."
            ),
            criteria=[
                "Routine: this rule and process are a regular part of this entity's history",
                "Somewhat new: seen rarely before, or the entity has little history",
                "Unlike anything in this entity's history",
            ],
        ),
        "account_mismatch": Score(
            instructions=(
                "Is this activity unexpected for this kind of account (`alert.account_type`)? "
                "For example, a service account running interactive discovery commands, or a normal "
                "user performing administrative actions."
            ),
            criteria=[
                "Typical for this account type",
                "Unusual for this account type but has plausible legitimate reasons",
                "Clearly inappropriate for this account type",
            ],
        ),
        "malicious_automation": Score(
            instructions=(
                "Does this look like malicious automation, such as beaconing, scanning, brute forcing, "
                "or a scripted attack chain, as opposed to routine scheduled jobs or human-paced work? "
                "Use `alert.repetition` for timing and count, and the rule, tactics and process."
            ),
            criteria=[
                "Human-paced activity or a routine scheduled job",
                "Automated, but plausibly legitimate tooling",
                "Malicious automation: beaconing, scanning, brute forcing, or scripted attack steps",
            ],
        ),
    }


@dataclass
class JevResult:
    scores: dict[str, float]           # normalized 0..1 per question
    confidence: dict[str, float]
    input_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0
    cached: bool = False

    def vector(self) -> list[float]:
        return [self.scores[q] for q in QUESTION_IDS]


class JevUnavailable(RuntimeError):
    """Jev couldn't answer (network, auth, rate limit, timeout or a bad response)."""


class Scorer(Protocol):
    def score_many(self, states: list[dict[str, Any]]) -> list[JevResult | JevUnavailable]: ...


def state_key(state: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(state, sort_keys=True).encode()).hexdigest()


class JevCache:
    """Append-only JSONL cache keyed by the payload hash, so tuning never calls Jev twice for the same input."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path else None
        self._mem: dict[str, dict] = {}
        if self.path and self.path.exists():
            for line in self.path.read_text().splitlines():
                if line.strip():
                    rec = json.loads(line)
                    self._mem[rec["key"]] = rec

    def get(self, key: str) -> JevResult | None:
        rec = self._mem.get(key)
        if not rec:
            return None
        return JevResult(rec["scores"], rec["confidence"], rec.get("in", 0), rec.get("out", 0), 0.0, True)

    def put(self, key: str, r: JevResult) -> None:
        rec = {"key": key, "scores": r.scores, "confidence": r.confidence, "in": r.input_tokens, "out": r.output_tokens}
        self._mem[key] = rec
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a") as f:
                f.write(json.dumps(rec) + "\n")


class JevScorer:
    """Scores lots of alerts at the same time. Failures come back as JevUnavailable instead of raising."""

    def __init__(self, cfg: JevConfig, cache: JevCache | None = None, api_key: str | None = None):
        self.cfg = cfg
        self.cache = cache or JevCache(None)
        self.api_key = api_key
        self.outbound_log: list[dict[str, Any]] = []   # every payload I send, for the leakage scan

    def score_many(self, states: list[dict[str, Any]]) -> list[JevResult | JevUnavailable]:
        return asyncio.run(self._score_many(states))

    async def _score_many(self, states):
        from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy

        questions = _questions()
        sem = asyncio.Semaphore(self.cfg.concurrency)
        results: list[JevResult | JevUnavailable | None] = [None] * len(states)
        todo = []
        for i, s in enumerate(states):
            hit = self.cache.get(state_key(s))
            if hit:
                results[i] = hit
            else:
                todo.append(i)
        if not todo:
            return results

        done = [0]
        retry = RetryPolicy(max_retries=self.cfg.max_retries, timeout=self.cfg.timeout_seconds)
        async with AsyncTypeSafeClient(api_key=self.api_key, model=self.cfg.model, retry=retry) as client:

            async def one(i: int):
                state = states[i]
                async with sem:
                    self.outbound_log.append(state)
                    t0 = time.perf_counter()
                    try:
                        resp = await client.system_one(state=state, questions=questions)
                        results[i] = _parse(resp, time.perf_counter() - t0)
                        self.cache.put(state_key(state), results[i])
                    except Exception as e:  # any failure here -> fall back to the local LLM
                        results[i] = JevUnavailable(f"{type(e).__name__}: {e}")
                    done[0] += 1
                    if len(todo) >= 1000 and done[0] % 1000 == 0:
                        print(f"  jev: {done[0]:,}/{len(todo):,}", file=sys.stderr, flush=True)

            await asyncio.gather(*(one(i) for i in todo))
        return results


def _parse(resp, latency: float) -> JevResult:
    scores, conf = {}, {}
    for q in QUESTION_IDS:
        ans = resp.answers[q]
        top = max(ans.legend.keys()) if ans.legend else 2
        scores[q] = float(ans.score) / float(top)
        conf[q] = float(ans.confidence)
    usage = resp.usage
    return JevResult(
        scores, conf,
        getattr(usage, "input_tokens", 0) or 0,
        getattr(usage, "output_tokens", 0) or 0,
        latency,
    )


class OfflineScorer:
    """Always unavailable. I use it for the 'Jev is down' test."""

    def __init__(self) -> None:
        self.outbound_log: list[dict[str, Any]] = []

    def score_many(self, states):
        return [JevUnavailable("Jev disabled") for _ in states]
