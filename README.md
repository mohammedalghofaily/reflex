# Reflex

Fast, private alert triage for SOC analysts. Jev scores every alert on four questions, a
logistic regression turns those into one suspicion score, and a local LLM (Qwen3 8B via
Ollama) decides only the uncertain middle. An entity risk store links low-severity alerts
over time so multi-stage attacks still surface. Raw logs never leave the premises.

Design write-up: https://www.mohammedalghofaily.com/work/reflex/

## Results

On a held-out test set of 705,028 real IDS alerts (AIT-ADS: wilson + shaw), Reflex v2 matched a
logistic-regression baseline's benign-alert resolution (79.8% vs 79.7%) with **56% fewer analyst
items** (436 vs 997), detecting 4/4 attack chains (14/15 steps). v1, the design as written, caught
15/15 steps but needed 3,238 analyst items. Jev cost about $0.0025 per 1,000 alerts.

Full numbers, findings, adversarial tests and limitations: **[RESULTS.md](RESULTS.md)**.

## Layout

| Module | What it does |
|---|---|
| `pseudonymize.py` | HMAC-SHA256 (written out step by step, checked against `hmac`), normalization, command line → exe + flags, outbound allow-list |
| `enrich.py` | ATT&CK tactics, per-entity baselines, network zone lookup |
| `grouping.py` | Merges identical alerts within a window |
| `outbound.py` | Builds the only payload that leaves: pseudonymized features |
| `jev.py` | Four `Score` questions in one request, concurrent, cached |
| `aggregator.py` | Logistic regression over Jev scores + severity + tactic (v1), plus familiarity features (v2); the no-Jev baseline |
| `pipeline.py` | Routing: auto-close / local LLM / analyst by suspicion (thresholds tuned on validation) |
| `llm.py` | Ollama client, JSON-schema output, temperature 0, any error → analyst; prompts v1 and v2 |
| `guards.py` | Non-LLM rules: instruction-like text → analyst; LLM may never close exfiltration/impact |
| `risk_store.py` | `risk_new = risk_old · 2^(−Δt/half_life) + max(0, suspicion − floor)`, tactic window, cooldown, incidents |
| `alert_db.py` | Every decision and why |
| `leakage.py` | Scans every outbound payload for raw usernames, hostnames, IPs, command lines |
| `data/ait_ads.py` | AIT-ADS loader (joins raw Wazuh/AMiner JSON with the labelled CSV row by row) |
| `evaluation/` | Metrics, training, validation tuning, baselines, adversarial tests, Markdown report |

## Setup

```bash
python -m venv .venv && .venv/bin/pip install -e '.[dev]'
ollama pull qwen3:8b
```

Secrets go in `.env` (git-ignored): `REFLEX_HMAC_KEY=<64 hex chars>` and `TYPESAFE_API_KEY=...`
from console.typesafe.ai.

Data in `data/`:
- `alerts_raw/`: unzip `ait_ads.zip` from https://zenodo.org/record/8263181.
- `alerts_csv/`: unzip `alerts_csv/alerts_csv.zip` from https://github.com/ait-aecid/alert-data-set (per-alert event labels).

## Run

```bash
reflex demo                                   # offline, synthetic data, stand-in models
reflex baseline    --data data                # logistic-regression baseline only (no API calls)
reflex train       --data data                # v1 aggregator
reflex tune        --data data                # santos; staged search, then freezes config
reflex evaluate    --data data --out results  # wilson + shaw, run once
reflex adversarial --data data --out results --payloads attacks.csv
```

Reflex v2 (Jev + familiarity features, alert-count weighting, all training groups):

```bash
.venv/bin/python scripts/train_aggregator_variants.py   # fits 4 variants into artifacts/candidates/
.venv/bin/python scripts/select_aggregator.py           # compares them on santos
reflex tune --data data --artifacts artifacts_v2 --grid artifacts_v2/stages.json
reflex evaluate --data data --artifacts artifacts_v2 --out results_v2 --skip-llm-only
```

The frozen configs actually used are `artifacts/v1/config.json` and `artifacts_v2/config.json`.
`results*/report.md` has targets vs achieved, the baselines, every attack step and every miss.
Jev and LLM answers are cached (`artifacts/*_cache.jsonl`), so tuning never re-calls them for the
same input.

## Honest limits

- `reflex demo` uses heuristic stand-ins for Jev and Qwen3. Its numbers say nothing about
  either model; only `evaluate` on AIT-ADS produces reportable results.
- Chains: each scenario has an "intrusion" chain and an "exfiltration" chain (service_stop, dnsteal). Override with a
  `{scenario: {step: chain}}` JSON if you split scenarios into several chains.
- Baselines are built on the training split and frozen (as in the design); scenarios share
  host names, so they carry over.
- The test set was evaluated twice (v1, then v2). See RESULTS.md for what that means.
