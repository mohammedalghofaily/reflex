"""Compares the 4 aggregator variants on santos (validation only) and picks the best one.

Qwen3 escalated every alert it saw on santos, so I use a stand-in that always escalates.
That way this doesn't fight the overnight run for the GPU.
"""
import json, pickle, sys, time
from pathlib import Path
from reflex.cli import load_dotenv; load_dotenv()
from reflex.config import Config, hmac_key_from_env
from reflex.data.ait_ads import load_split
from reflex.aggregator import Aggregator, BaselineModel
from reflex.jev import JevScorer, JevCache
from reflex.llm import LLMVerdict
from reflex.pseudonymize import Pseudonymizer
from reflex.evaluation.experiments import run_reflex, run_lr_baseline, train_lr_baseline


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", file=sys.stderr, flush=True)


class Escalate:
    def judge(self, *a): return LLMVerdict("needs_human", "stand-in")


cfg = Config.load('artifacts/config.json'); p = Pseudonymizer(hmac_key_from_env())
val = load_split('data', 'validation')
cand = Path('artifacts/candidates')
bl = pickle.loads((cand / 'baselines.pkl').read_bytes())
scorer = JevScorer(cfg.jev, JevCache('artifacts/jev_cache.jsonl'))
rows = []

lr = BaselineModel.load('artifacts/v1/lr_baseline.pkl')
t = json.loads(Path('artifacts/v1/lr_threshold.json').read_text())['threshold']
m = run_lr_baseline(val, cfg, p, lr, bl, t).metrics
rows.append({"system": "LR baseline", "auto_close_max": round(t, 3), "recall": m["per_step_recall"],
             "resolved": m["benign_auto_resolve_jev"], "analyst_items": m["analyst_items"]})
log(f"LR baseline on santos: {rows[-1]}")

for name in ("v1_none", "v1_alerts", "v2_none", "v2_alerts"):
    agg = Aggregator.load(cand / f"agg_{name}.pkl")
    best = None
    for ac in (0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95):
        c = Config.from_dict(cfg.to_dict())
        c.routing.auto_close_max, c.routing.analyst_min = ac, max(ac + 0.01, cfg.routing.analyst_min)
        m = run_reflex(val, c, p, scorer, Escalate(), agg, bl)[0].metrics
        row = {"system": name, "auto_close_max": ac, "recall": m["per_step_recall"],
               "resolved": m["benign_auto_resolve_jev"], "analyst_items": m["analyst_items"]}
        rows.append(row)
        log(str(row))
        if m["per_step_recall"] == 1.0 and (best is None or (row["resolved"], -row["analyst_items"]) > (best["resolved"], -best["analyst_items"])):
            best = row
    log(f"BEST {name}: {best}")

Path('artifacts/candidates/selection.json').write_text(json.dumps(rows, indent=1))
log("done")
