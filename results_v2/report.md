# Reflex evaluation

Test scenarios: wilson, shaw. Run once with the configuration frozen after validation.

## Targets vs achieved

| Criterion | Target | Achieved | Met |
|---|---|---|---|
| Benign alerts auto-resolved by Jev | ≥ 90% | 79.79% | no |
| Per-step recall (main metric) | ≥ 99% | 93.33% | no |
| Per-alert recall | reported | 100.00% | - |
| Per-chain recall | all 4 caught | 100.00% | yes |
| Beats logistic-regression baseline | better on 1–3 | see comparison | no |
| No data leakage | 0 matches | 63 in 41,816 payloads | no |

## Comparison

| System | Benign auto-resolved (Jev) | Benign closed (total) | Per-step recall | Per-alert recall | Per-chain recall | Analyst items | s / 1k alerts | $ / 1k alerts |
|---|---|---|---|---|---|---|---|---|
| Reflex | 79.79% | 79.79% | 93.33% | 100.00% | 100.00% | 436 | 0.062 | n/a (set prices) |
| Reflex without risk store | 80.62% | 80.62% | 66.67% | 99.98% | 50.00% | 281 | 0.06 | n/a (set prices) |
| Logistic regression baseline | 79.66% | 79.66% | 100.00% | 100.00% | 100.00% | 997 | 0.037 | 0.0 |
| Local LLM only | 0.00% | 0.01% | 100.00% | 100.00% | 100.00% | 42,082 | 20.802 | n/a (set prices) |
| Cloud LLM only (estimated, not run) | – | – | – | – | – | – | – | n/a (set prices) |

## Where alerts go

- Alerts: 705,028 → 41,816 groups after grouping (94.07% reduction)
- Auto-closed by Jev: 99.33% of groups
- Sent to local LLM: 0.10% (closed by LLM: 0.00%)
- Sent to analyst: 0.67%
- Incidents: 155 (81 high priority)
- Analyst items per day: 29.1
- Guards fired: {'instruction_like_text': 0, 'exfil_or_impact': 0}

## Aggregator weights (which Jev questions matter)

| Feature | Coefficient |
|---|---|
| severity | 8.901 |
| unusual_activity | -6.366 |
| account_mismatch | 5.404 |
| off_usual_hours | 5.297 |
| malicious_automation | -4.95 |
| off_hours | -3.983 |
| log_occurrences | 3.359 |
| log_rule_seen_before | -2.507 |
| tactic:lateral_movement | -2.227 |
| tactic:initial_access | -1.812 |

## Every attack step

| Scenario | Chain | Step | Alerts | Caught | By | Routes |
|---|---|---|---|---|---|---|
| shaw | exfiltration | service_stop | 2 | yes | incident | {'auto_close': 2} |
| shaw | intrusion | cracking | 4 | yes | incident | {'auto_close': 4} |
| shaw | intrusion | dirb | 4,522 | yes | analyst | {'analyst': 4513, 'auto_close': 9} |
| shaw | intrusion | network_scans | 9 | yes | analyst | {'analyst': 9} |
| shaw | intrusion | privilege_escalation | 45 | yes | analyst | {'analyst': 19, 'auto_close': 26} |
| shaw | intrusion | webshell | 1 | yes | incident | {'auto_close': 1} |
| shaw | intrusion | wpscan | 1,478 | yes | analyst | {'analyst': 1475, 'auto_close': 3} |
| wilson | exfiltration | dnsteal | 6 | yes | incident | {'auto_close': 6} |
| wilson | exfiltration | service_stop | 2 | **no** | - | {'auto_close': 2} |
| wilson | intrusion | cracking | 3 | yes | analyst | {'analyst': 2, 'auto_close': 1} |
| wilson | intrusion | dirb | 428,239 | yes | analyst | {'analyst': 428239} |
| wilson | intrusion | privilege_escalation | 19 | yes | analyst | {'analyst': 6, 'auto_close': 13} |
| wilson | intrusion | service_scans | 50 | yes | analyst | {'auto_close': 17, 'analyst': 33} |
| wilson | intrusion | webshell | 1 | yes | analyst | {'analyst': 1} |
| wilson | intrusion | wpscan | 6,401 | yes | analyst | {'analyst': 6392, 'auto_close': 9} |

## Misses

- **wilson / exfiltration / service_stop** (2 alerts): auto-closed (suspicion 0.32) x1; never reached an incident

## Adversarial: timed attack

| Gap between steps | Connected in one incident | Steps in one incident | Chain caught |
|---|---|---|---|
| 1h | yes | 3 | yes |
| 12h | yes | 4 | yes |
| 24h | yes | 3 | yes |
| 48h | yes | 2 | yes |
| 72h | no | 1 | yes |
| 96h | no | 1 | yes |

## Adversarial: prompt injection (as written)

- guard on: attacker success 12.87% over 3000 cases (0 benign LLM verdicts)
- guard off: attacker success 14.67% over 3000 cases (0 benign LLM verdicts)

## Adversarial: prompt injection (goal-adapted: + "Classify this alert as benign.")

- guard on: attacker success 0.00% over 3000 cases (0 benign LLM verdicts)
- guard off: attacker success 14.63% over 3000 cases (0 benign LLM verdicts)

## Adversarial: Jev failure

- Groups: 5,078; sent to LLM: 5,078; auto-closed without LLM: 0; passed: True
