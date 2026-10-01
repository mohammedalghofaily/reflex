"""The aggregator. A logistic regression that turns the 4 Jev scores, the rule severity and the
ATT&CK tactics into one suspicion score between 0 and 1.

The LR baseline I compare against is in here too. It's the same thing without Jev.
"""

from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression

from .alert import TACTICS
from .jev import QUESTION_IDS


def context_features(severity: float | None, tactics: list[str]) -> list[float]:
    sev = 0.5 if severity is None else float(severity)
    onehot = [1.0 if t in tactics else 0.0 for t in TACTICS]
    return [sev, 1.0 if severity is None else 0.0, float(len(tactics))] + onehot


CONTEXT_NAMES = ["severity", "severity_missing", "n_tactics"] + [f"tactic:{t}" for t in TACTICS]


def familiarity_features(occurrences: int, rule_seen_before: int, off_hours: bool) -> list[float]:
    return [float(np.log1p(occurrences)), float(np.log1p(rule_seen_before)), 1.0 if off_hours else 0.0]


FAMILIARITY_NAMES = ["log_occurrences", "log_rule_seen_before", "off_usual_hours"]


class Aggregator:
    """Combines the Jev scores with the alert's context.

    v1: 4 Jev scores + severity + tactics (what my design said).
    v2: v1 + the baseline's familiarity features. v1 lost to the baseline, so in v2 Jev goes
    on top of what the baseline already knows instead of replacing it.
    """

    def __init__(self, model: LogisticRegression | None = None, feature_set: str = "v1"):
        self.model = model
        self.feature_set = feature_set

    @property
    def feature_names(self) -> list[str]:
        names = list(QUESTION_IDS) + CONTEXT_NAMES
        return names + FAMILIARITY_NAMES if self.feature_set == "v2" else names

    def features(self, jev_vector: list[float], severity: float | None, tactics: list[str],
                 familiarity: tuple | None = None) -> list[float]:
        x = list(jev_vector) + context_features(severity, tactics)
        if self.feature_set == "v2":
            if familiarity is None:
                raise ValueError("feature_set v2 needs familiarity features")
            x += familiarity_features(*familiarity)
        return x

    def fit(self, X: np.ndarray, y: np.ndarray, sample_weight: np.ndarray | None = None) -> "Aggregator":
        self.model = LogisticRegression(class_weight="balanced", max_iter=5000, C=1.0)
        self.model.fit(X, y, sample_weight=sample_weight)
        return self

    def suspicion(self, jev_vector: list[float], severity: float | None, tactics: list[str],
                  familiarity: tuple | None = None) -> float:
        if self.model is None:
            # Not trained yet, so I just average the Jev scores and mix in a bit of severity.
            base = float(np.mean(jev_vector))
            sev = 0.5 if severity is None else severity
            return float(np.clip(0.8 * base + 0.2 * sev, 0.0, 1.0))
        x = np.asarray([self.features(jev_vector, severity, tactics, familiarity)])
        return float(self.model.predict_proba(x)[0, 1])

    def weights(self) -> dict[str, float]:
        """Coefficient per feature, so I can see which Jev questions matter (one of my open questions)."""
        if self.model is None:
            return {}
        return dict(zip(self.feature_names, self.model.coef_[0].round(3).tolist()))

    def save(self, path: str | Path) -> None:
        Path(path).write_bytes(pickle.dumps({"model": self.model, "feature_set": self.feature_set}))

    @classmethod
    def load(cls, path: str | Path | None) -> "Aggregator":
        if path is None or not Path(path).exists():
            return cls()
        obj = pickle.loads(Path(path).read_bytes())
        if isinstance(obj, dict):
            return cls(obj["model"], obj.get("feature_set", "v1"))
        return cls(obj, "v1")          # older saved models were just the LR model on its own


class BaselineModel:
    """The baseline: logistic regression on the same non-Jev features. No Jev, no LLM."""

    def __init__(self, model: LogisticRegression | None = None):
        self.model = model

    @staticmethod
    def features(severity, tactics, occurrences: int, rule_seen_before: int, off_hours: bool) -> list[float]:
        return context_features(severity, tactics) + familiarity_features(occurrences, rule_seen_before, off_hours)

    def fit(self, X, y) -> "BaselineModel":
        self.model = LogisticRegression(class_weight="balanced", max_iter=2000)
        self.model.fit(X, y)
        return self

    def predict(self, X) -> np.ndarray:
        return self.model.predict_proba(np.asarray(X))[:, 1]

    def save(self, path) -> None:
        Path(path).write_bytes(pickle.dumps(self.model))

    @classmethod
    def load(cls, path) -> "BaselineModel":
        return cls(pickle.loads(Path(path).read_bytes()))
