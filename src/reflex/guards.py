"""Rules that don't depend on the LLM at all.

A JSON schema only controls the format of the LLM's answer, not the answer itself. These
checks limit what any model is allowed to decide.
"""

from __future__ import annotations

import base64
import re

from .alert import Alert

NEVER_AUTO_CLOSE_TACTICS = frozenset({"exfiltration", "impact"})

_INSTRUCTION_PATTERNS = [
    r"\bignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier)\b",
    r"\bdisregard\b.{0,40}\b(instruction|rule|prompt|above)",
    r"\b(classify|mark|label|treat|flag)\s+(this|it|the alert|as)\b.{0,30}\b(benign|safe|harmless|false positive|clean)\b",
    r"\bnote\s+to\s+(the\s+)?(ai|llm|model|assistant|analyst bot)\b",
    r"\b(you are|act as|as an ai|you must|you should)\b.{0,40}\b(model|assistant|ai|classif|respond|answer)",
    r"\b(system|developer)\s*(prompt|message|instruction)s?\b",
    r"\bnew\s+instructions?\b",
    r"\bapproved\b.{0,40}\b(maintenance|by it|by security|script|activity)\b",
    r"\b(verdict|output|respond|answer)\s*[:=]\s*[\"']?benign\b",
    r"</?(system|assistant|user|instructions?)>",
    r"\[/?INST\]|<\|im_(start|end)\|>",
    r"\bneeds_human\b|\"verdict\"",
]
_INSTRUCTION_RE = re.compile("|".join(_INSTRUCTION_PATTERNS), re.I | re.S)
_B64_RE = re.compile(r"(?:-e(?:nc(?:odedcommand)?)?\s+)([A-Za-z0-9+/=]{16,})", re.I)


def _decoded_payloads(text: str) -> list[str]:
    """PowerShell -enc payloads are base64 UTF-16LE, so I decode them and check inside too."""
    out = []
    for m in _B64_RE.finditer(text):
        blob = m.group(1)
        for enc in ("utf-16-le", "utf-8"):
            try:
                out.append(base64.b64decode(blob + "=" * (-len(blob) % 4)).decode(enc))
                break
            except Exception:
                continue
    return out


def looks_like_instructions(text: str) -> bool:
    if _INSTRUCTION_RE.search(text):
        return True
    return any(_INSTRUCTION_RE.search(d) for d in _decoded_payloads(text))


def injection_fields(alert: Alert) -> list[str]:
    """Returns the fields whose text reads like instructions to a model."""
    hits = [name for name, v in alert.string_fields().items() if looks_like_instructions(v)]
    for k, v in _flatten(alert.raw):
        if isinstance(v, str) and len(v) > 12 and looks_like_instructions(v):
            hits.append(f"raw.{k}")
    return hits


def _flatten(d, prefix=""):
    if isinstance(d, dict):
        for k, v in d.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(d, list):
        for i, v in enumerate(d[:50]):
            yield from _flatten(v, f"{prefix}[{i}]")
    else:
        yield prefix, d


def may_llm_close(tactics: list[str]) -> bool:
    return not (set(tactics) & NEVER_AUTO_CLOSE_TACTICS)
