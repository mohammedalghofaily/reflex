"""Scores every training group with Jev once, then fits 4 aggregator variants from it
(v1 or v2 features, with or without alert weighting). This is how I built Reflex v2.

Run from the repo root: .venv/bin/python scripts/train_aggregator_variants.py
Saves everything to artifacts/candidates/.
"""
import json, pickle, sys, time
from pathlib import Path
import numpy as np
from reflex.cli import load_dotenv; load_dotenv()
from reflex.config import Config, hmac_key_from_env
from reflex.data.ait_ads import load_split
from reflex.aggregator import Aggregator, BaselineModel
from reflex.jev import JevScorer, JevCache, JevResult
from reflex.pseudonymize import Pseudonymizer
from reflex.outbound import build_state, familiarity
from reflex.evaluation.experiments import prepare_groups, build_baselines
def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", file=sys.stderr, flush=True)
cfg = Config.load('artifacts/config.json'); p = Pseudonymizer(hmac_key_from_env())
groups = prepare_groups(load_split('data', 'train'), cfg)
baselines = build_baselines(groups, p)
log(f"scoring all {len(groups):,} training groups")
states = [build_state(g, g.representative.tactics, p, baselines) for g in groups]
res = JevScorer(cfg.jev, JevCache('artifacts/jev_cache.jsonl')).score_many(states)
ok = [(g, r) for g, r in zip(groups, res) if isinstance(r, JevResult)]
log(f"{len(ok):,} scored, {len(groups) - len(ok)} failures")
y = np.array([int(bool(g.is_attack)) for g, _ in ok])
out = Path('artifacts/candidates'); out.mkdir(exist_ok=True)
info = {}
for fs in ("v1", "v2"):
    for wt in ("none", "alerts"):
        agg = Aggregator(feature_set=fs)
        X = np.array([agg.features(r.vector(), g.representative.severity, g.representative.tactics,
                                   familiarity(g, p, baselines)) for g, r in ok])
        w = np.array([np.sqrt(g.count) if wt == "alerts" else 1.0 for g, _ in ok])
        agg.fit(X, y, w); agg.save(out / f"agg_{fs}_{wt}.pkl")
        info[f"{fs}_{wt}"] = agg.weights(); log(f"fitted {fs}/{wt}")
(out / "baselines.pkl").write_bytes(pickle.dumps(baselines))
(out / "info.json").write_text(json.dumps({"train_groups": len(ok), "failures": len(groups) - len(ok), "weights": info}, indent=1))
log("done")
