# Reflex evaluation

Test scenarios: wilson, shaw. Run once with the configuration frozen after validation.

## Targets vs achieved

| Criterion | Target | Achieved | Met |
|---|---|---|---|
| Benign alerts auto-resolved by Jev | ≥ 90% | 60.68% | no |
| Per-step recall (main metric) | ≥ 99% | 100.00% | yes |
| Per-alert recall | reported | 100.00% | - |
| Per-chain recall | all 4 caught | 100.00% | yes |
| Beats logistic-regression baseline | better on 1–3 | see comparison | no |
| No data leakage | 0 matches | 63 in 41,816 payloads | no |

## Comparison

| System | Benign auto-resolved (Jev) | Benign closed (total) | Per-step recall | Per-alert recall | Per-chain recall | Analyst items | s / 1k alerts | $ / 1k alerts |
|---|---|---|---|---|---|---|---|---|
| Reflex | 60.68% | 60.68% | 100.00% | 100.00% | 100.00% | 3,238 | 1.43 | n/a (set prices) |
| Reflex without risk store | 61.59% | 61.59% | 100.00% | 100.00% | 100.00% | 2,935 | 0.307 | n/a (set prices) |
| Logistic regression baseline | 79.66% | 79.66% | 100.00% | 100.00% | 100.00% | 997 | 0.037 | 0.0 |
| Local LLM only | 0.00% | 0.01% | 100.00% | 100.00% | 100.00% | 42,082 | 20.802 | n/a (set prices) |
| Cloud LLM only (estimated, not run) | – | – | – | – | – | – | – | n/a (set prices) |

## Where alerts go

- Alerts: 705,028 → 41,816 groups after grouping (94.07% reduction)
- Auto-closed by Jev: 92.98% of groups
- Sent to local LLM: 1.38% (closed by LLM: 0.00%)
- Sent to analyst: 7.02%
- Incidents: 303 (128 high priority)
- Analyst items per day: 216.0
- Guards fired: {'instruction_like_text': 0, 'exfil_or_impact': 0}

## Aggregator weights (which Jev questions matter)

| Feature | Coefficient |
|---|---|
| severity | 15.46 |
| unusual_activity | 13.759 |
| tactic:initial_access | -4.561 |
| tactic:credential_access | 3.371 |
| tactic:defense_evasion | 3.336 |
| tactic:privilege_escalation | 3.302 |
| account_mismatch | 2.828 |
| severity_missing | 2.471 |
| tactic:lateral_movement | -1.877 |
| tactic:persistence | -1.625 |

## Every attack step

| Scenario | Chain | Step | Alerts | Caught | By | Routes |
|---|---|---|---|---|---|---|
| shaw | exfiltration | service_stop | 2 | yes | analyst | {'analyst': 2} |
| shaw | intrusion | cracking | 4 | yes | analyst | {'analyst': 4} |
| shaw | intrusion | dirb | 4,522 | yes | analyst | {'analyst': 4522} |
| shaw | intrusion | network_scans | 9 | yes | analyst | {'analyst': 9} |
| shaw | intrusion | privilege_escalation | 45 | yes | analyst | {'analyst': 45} |
| shaw | intrusion | webshell | 1 | yes | analyst | {'analyst': 1} |
| shaw | intrusion | wpscan | 1,478 | yes | analyst | {'analyst': 1478} |
| wilson | exfiltration | dnsteal | 6 | yes | analyst | {'analyst': 6} |
| wilson | exfiltration | service_stop | 2 | yes | analyst | {'analyst': 2} |
| wilson | intrusion | cracking | 3 | yes | analyst | {'analyst': 3} |
| wilson | intrusion | dirb | 428,239 | yes | analyst | {'analyst': 428239} |
| wilson | intrusion | privilege_escalation | 19 | yes | analyst | {'analyst': 19} |
| wilson | intrusion | service_scans | 50 | yes | analyst | {'analyst': 50} |
| wilson | intrusion | webshell | 1 | yes | analyst | {'analyst': 1} |
| wilson | intrusion | wpscan | 6,401 | yes | analyst | {'analyst': 6392, 'auto_close': 9} |

## Misses

None.
