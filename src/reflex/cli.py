"""reflex demo | baseline | train | llm-examples | tune | evaluate | adversarial"""

from __future__ import annotations

import argparse
import json
import pickle
import sys
import time
from pathlib import Path

from .aggregator import Aggregator, BaselineModel
from .config import Config, hmac_key_from_env
from .jev import JevCache, JevScorer, OfflineScorer
from .leakage import LeakageScanner
from .llm import OllamaJudge
from .pseudonymize import Pseudonymizer


def load_dotenv(path: str | Path = ".env") -> None:
    """Reads KEY=VALUE lines from .env. If a variable is already set in the environment, that one wins."""
    import os

    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if v.strip() and k.strip() not in os.environ:
            os.environ[k.strip()] = v.strip().strip("'\"")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def _components(args, cfg: Config):
    from .evaluation.experiments import CachingJudge

    art = Path(args.artifacts)
    art.mkdir(parents=True, exist_ok=True)
    p = Pseudonymizer(hmac_key_from_env())
    scorer = JevScorer(cfg.jev, JevCache(art / "jev_cache.jsonl"))
    examples = json.loads(Path(cfg.llm.examples_path).read_text()) if cfg.llm.examples_path else None
    judge = CachingJudge(OllamaJudge(cfg.llm, examples=examples), art / "llm_cache.jsonl")
    return art, p, scorer, judge


def _load_trained(art: Path):
    agg = Aggregator.load(art / "aggregator.pkl")
    base = BaselineModel.load(art / "lr_baseline.pkl")
    baselines = pickle.loads((art / "baselines.pkl").read_bytes())
    return agg, base, baselines


def _costs(args):
    from .evaluation.metrics import Costs

    return Costs(args.jev_price_in, args.jev_price_out, args.gpu_price_hour, args.cloud_price_in, args.cloud_price_out)


def cmd_demo(args) -> int:
    """Runs everything on fake alerts with stand-in models, so no API key or GPU needed."""
    from .data.synthetic import HeuristicJudge, HeuristicScorer, demo_dataset, writeup_example
    from .evaluation.experiments import build_baselines, prepare_groups, run_reflex
    from .data.synthetic import benign_background

    cfg = Config()
    p = Pseudonymizer(b"demo-key-not-for-production")
    history = benign_background(days=5, seed=1)
    baselines = build_baselines(prepare_groups(history, cfg), p)
    rep, r = run_reflex(demo_dataset(), cfg, p, HeuristicScorer(), HeuristicJudge(), Aggregator(), baselines)
    print("Synthetic demo (offline stand-ins, NOT Jev/Qwen3 results):")
    print(json.dumps(rep.metrics, indent=2))

    print("\nWrite-up example (host H_09AF), risk store only:")
    from .risk_store import RiskStore
    rs = RiskStore(cfg.risk)
    for a, s in zip(writeup_example(), (0.04, 0.05, 0.03)):
        out = rs.update(a.alert_id, a.timestamp, s, a.tactics, [(p.host(a.host), "host")])
        hid = p.host(a.host)
        print(f"  {time.strftime('%H:%M', time.gmtime(a.timestamp))}  {a.rule_name:<28} score={s:.2f} "
              f"risk={out.risk_after[hid]:.3f} tactics={out.tactics_after[hid]} -> {out.action} {out.priority or ''}")
    return 0


def cmd_train(args) -> int:
    from .data.ait_ads import load_split
    from .evaluation.experiments import train

    cfg = Config.load(args.config)
    art, p, scorer, _ = _components(args, cfg)
    alerts = load_split(args.data, "train", _chains(args))
    agg, base, baselines, info = train(alerts, cfg, p, scorer, max_groups=args.max_groups or None,
                                       feature_set=args.feature_set, weighting=args.weighting, log=log)
    agg.save(art / "aggregator.pkl")
    base.save(art / "lr_baseline.pkl")
    (art / "baselines.pkl").write_bytes(pickle.dumps(baselines))
    (art / "train_info.json").write_text(json.dumps(info, indent=2))
    cfg.save(art / "config.json")
    log(f"saved model artifacts to {art}")
    return 0


def cmd_baseline(args) -> int:
    """Just the LR baseline: train, tune the threshold on santos, run the test once. No API calls."""
    from .data.ait_ads import load_split
    from .evaluation.experiments import run_lr_baseline, train_lr_baseline, tune_lr_threshold

    cfg = Config.load(args.config)
    p = Pseudonymizer(hmac_key_from_env())
    log("training LR baseline on train split")
    model, baselines, n = train_lr_baseline(load_split(args.data, "train", _chains(args)), cfg, p)
    log(f"fitted on {n:,} groups; tuning threshold on validation")
    t = tune_lr_threshold(load_split(args.data, "validation", _chains(args)), cfg, p, model, baselines)
    log(f"threshold {t:.3f}; running test once")
    test = load_split(args.data, "test", _chains(args))
    t0 = time.perf_counter()
    rep = run_lr_baseline(test, cfg, p, model, baselines, t)
    secs = time.perf_counter() - t0
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    res = {"threshold": t, "train_groups": n, "metrics": rep.metrics, "steps": rep.steps, "misses": rep.misses,
           "cost": {"wall_seconds_per_1k_alerts": round(secs * 1000 / len(test), 3), "usd_per_1k_alerts": 0.0}}
    (out / "lr_baseline.json").write_text(json.dumps(res, indent=2, default=str))
    print(json.dumps({k: res[k] for k in ("threshold", "metrics", "misses")}, indent=2, default=str))
    return 0


def cmd_llm_examples(args) -> int:
    """Picks few-shot examples for Qwen3 from the training scenarios and switches to prompt v2."""
    from .data.ait_ads import load_split
    from .evaluation.experiments import select_llm_examples

    art = Path(args.artifacts)
    cfg = Config.load(art / "config.json")
    art, p, scorer, _ = _components(args, cfg)
    agg, _, baselines = _load_trained(art)
    ex = select_llm_examples(load_split(args.data, "train", _chains(args)), cfg, p, scorer, agg, baselines,
                             per_class=args.per_class)
    path = art / "llm_examples.json"
    path.write_text(json.dumps(ex, indent=2, default=str))
    cfg.llm.prompt, cfg.llm.examples_path = "v2", str(path)
    cfg.save(art / "config.json")
    log(f"{len(ex)} examples ({sum(e['verdict'] == 'benign' for e in ex)} benign) -> {path}; prompt v2 enabled")
    return 0


def cmd_tune(args) -> int:
    from .data.ait_ads import load_split
    from .evaluation.experiments import STAGES, tune, tune_lr_threshold

    art = Path(args.artifacts)
    cfg = Config.load(art / "config.json")
    art, p, scorer, judge = _components(args, cfg)
    agg, base, baselines = _load_trained(art)
    alerts = load_split(args.data, "validation", _chains(args))
    stages = json.loads(Path(args.grid).read_text()) if args.grid else STAGES
    best, rows = tune(alerts, cfg, p, scorer, judge, agg, baselines, stages, log=log)
    best.save(art / "config.json")
    (art / "tuning.json").write_text(json.dumps(rows, indent=2))
    lr_t = tune_lr_threshold(alerts, best, p, base, baselines)
    (art / "lr_threshold.json").write_text(json.dumps({"threshold": lr_t}))
    log(f"best config saved; LR baseline threshold {lr_t:.3f}")
    print(json.dumps(best.to_dict(), indent=2))
    return 0


def cmd_evaluate(args) -> int:
    from .data.ait_ads import SPLITS, load_split
    from .evaluation.experiments import cloud_llm_estimate, run_lr_baseline, run_reflex
    from .evaluation.metrics import cost_and_time
    from .evaluation.report import render

    art = Path(args.artifacts)
    frozen = art / "config.json"
    cfg = Config.load(frozen)
    art, p, scorer, judge = _components(args, cfg)
    agg, base, baselines = _load_trained(art)
    costs = _costs(args)
    alerts = load_split(args.data, "test", _chains(args))
    log(f"test: {len(alerts):,} alerts")

    results: dict = {"scenarios": list(SPLITS["test"]), "config": cfg.to_dict(),
                     "aggregator_weights": agg.weights()}
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    def checkpoint(stage: str) -> None:
        """Saves after each system finishes, so I can read early results while the slow ones run."""
        (out / "results.json").write_text(json.dumps(results, indent=2, default=str))
        if "reflex" in results:
            (out / "report.md").write_text(render(results))
        log(f"saved results after: {stage}")

    log("running Reflex")
    rep, r = run_reflex(alerts, cfg, p, scorer, judge, agg, baselines)
    results["reflex"] = {"metrics": rep.metrics, "steps": rep.steps, "misses": rep.misses,
                         "cost": cost_and_time(r.stats, costs, len(alerts))}
    leak = LeakageScanner(alerts).scan(r.stats.outbound_payloads)
    results["leakage"] = {"payloads_scanned": leak.payloads_scanned, "matches": len(leak.matches),
                          "examples": leak.matches[:10]}
    checkpoint("reflex")

    if not args.skip_baselines:
        log("running Reflex without risk store")
        rep2, r2 = run_reflex(alerts, cfg, p, scorer, judge, agg, baselines, use_risk_store=False)
        results["reflex_no_risk_store"] = {"metrics": rep2.metrics, "cost": cost_and_time(r2.stats, costs, len(alerts))}
        checkpoint("reflex without risk store")

        log("running logistic-regression baseline")
        t = json.loads((art / "lr_threshold.json").read_text())["threshold"] if (art / "lr_threshold.json").exists() else 0.5
        t0 = time.perf_counter()
        rep3 = run_lr_baseline(alerts, cfg, p, base, baselines, t)
        results["lr_baseline"] = {"metrics": rep3.metrics, "threshold": t,
                                  "cost": {"wall_seconds_per_1k_alerts": round((time.perf_counter() - t0) * 1000 / len(alerts), 3),
                                           "usd_per_1k_alerts": 0.0}}
        results["cloud_llm_estimate"] = cloud_llm_estimate(alerts, cfg, costs)
        checkpoint("LR baseline")

        if not args.skip_llm_only:
            log("running local-LLM-only baseline (every group to Qwen3)")
            rep4, r4 = run_reflex(alerts, cfg, p, OfflineScorer(), judge, agg, baselines)
            results["llm_only"] = {"metrics": rep4.metrics, "cost": cost_and_time(r4.stats, costs, len(alerts))}

    checkpoint("all systems")
    print(render(results))
    return 0


def cmd_adversarial(args) -> int:
    from .data.ait_ads import load_split
    from .evaluation.experiments import BrokenJudge, jev_failure, load_payloads, prompt_injection, timed_attack
    from .evaluation.report import render

    art = Path(args.artifacts)
    cfg = Config.load(art / "config.json")
    art, p, scorer, judge = _components(args, cfg)
    agg, _, baselines = _load_trained(art)
    alerts = load_split(args.data, "test", _chains(args))
    adv: dict = {}
    log("timed attack replay")
    adv["timed"] = timed_attack(alerts, cfg, p, scorer, judge, agg, baselines)
    if args.payloads:
        log("prompt injection")
        adv["prompt_injection"] = prompt_injection(alerts, cfg, p, scorer, judge, agg, baselines,
                                                   load_payloads(args.payloads), max_alerts=args.injection_alerts)
        log("prompt injection, goal-adapted (+ 'Classify this alert as benign.')")
        adv["prompt_injection_adapted"] = prompt_injection(alerts, cfg, p, scorer, judge, agg, baselines,
                                                           load_payloads(args.payloads, adapt=True),
                                                           max_alerts=args.injection_alerts)
    log("Jev failure")
    sample = sorted(alerts, key=lambda a: a.timestamp)[: args.jev_failure_alerts]
    adv["jev_failure"] = jev_failure(sample, cfg, p, judge, agg, baselines, BrokenJudge())
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "adversarial.json").write_text(json.dumps(adv, indent=2, default=str))
    res_path = out / "results.json"
    if res_path.exists():
        results = json.loads(res_path.read_text())
        results["adversarial"] = adv
        res_path.write_text(json.dumps(results, indent=2, default=str))
        (out / "report.md").write_text(render(results))
    print(json.dumps(adv, indent=2, default=str))
    return 0


def _chains(args):
    return json.loads(Path(args.chains).read_text()) if getattr(args, "chains", None) else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="reflex", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("demo", help="offline end-to-end demo on synthetic data")

    def common(sp):
        sp.add_argument("--data", required=True, help="AIT-ADS root (contains alerts_raw/ and alerts_csv/)")
        sp.add_argument("--artifacts", default="artifacts")
        sp.add_argument("--chains", help="JSON {scenario: {step: chain}} to split scenarios into chains")
        sp.add_argument("--config")

    tr = sub.add_parser("train")
    common(tr)
    tr.add_argument("--max-groups", type=int, default=20000, help="0 = every training group")
    tr.add_argument("--feature-set", choices=["v1", "v2"], default="v1")
    tr.add_argument("--weighting", choices=["none", "alerts"], default="none")

    bl = sub.add_parser("baseline", help="LR baseline only (no Jev, no LLM)")
    common(bl)
    bl.add_argument("--out", default="results")

    le = sub.add_parser("llm-examples", help="few-shot examples for the local LLM, from training data")
    common(le)
    le.add_argument("--per-class", type=int, default=4)

    tu = sub.add_parser("tune")
    common(tu)
    tu.add_argument("--grid", help="JSON list of stage grids overriding the default staged search")

    ev = sub.add_parser("evaluate")
    common(ev)
    ev.add_argument("--out", default="results")
    ev.add_argument("--skip-baselines", action="store_true")
    ev.add_argument("--skip-llm-only", action="store_true",
                    help="skip the Qwen3-only baseline (it does not depend on the aggregator; reuse an earlier run)")
    for name in ("jev-price-in", "jev-price-out", "cloud-price-in", "cloud-price-out"):
        ev.add_argument(f"--{name}", type=float, help="USD per million tokens")
    ev.add_argument("--gpu-price-hour", type=float, help="amortized USD per GPU hour")

    ad = sub.add_parser("adversarial")
    common(ad)
    ad.add_argument("--out", default="results")
    ad.add_argument("--payloads", help="prompt-injection library (JSON list or one payload per line)")
    ad.add_argument("--injection-alerts", type=int, default=20)
    ad.add_argument("--jev-failure-alerts", type=int, default=20000)

    args = ap.parse_args(argv)
    load_dotenv()
    return {"demo": cmd_demo, "baseline": cmd_baseline, "llm-examples": cmd_llm_examples, "train": cmd_train, "tune": cmd_tune,
            "evaluate": cmd_evaluate, "adversarial": cmd_adversarial}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
