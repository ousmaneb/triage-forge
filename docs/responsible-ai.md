# Responsible AI and NIST AI RMF mapping

How the service addresses the four functions of the NIST AI Risk Management Framework (AI RMF 1.0).

## Govern

- Containment actions (`isolate_host`, `disable_account`, `block_ip`, `kill_process`) are never executed by the service. They are proposed, held in `pending_approval`, and need an analyst decision through `/alerts/{id}/decisions`.
- Every verdict and every analyst decision is written to an append-only JSONL audit log with the provider, risk score, actions, and guardrail flags.
- The model, effort level, and provider are configuration, recorded in `/health` and in each result, so any verdict can be traced to the system that produced it.

## Map

- Intended use: help SOC analysts prioritize and document alerts. Not intended to close alerts without review or to act on systems autonomously.
- Known risks: prompt injection through attacker-controlled fields, overconfident benign verdicts, citation of sources that were not retrieved, leakage of personal data to a third-party model, and drift between synthetic training data and real alerts.
- Each risk has a control below and a measurement in `eval/`.

## Measure

`eval/run_eval.py` measures, on held-out data:

- risk model ROC AUC, precision, recall, F1
- technique classification accuracy
- retrieval hit rate using alert text only
- end-to-end verdict accuracy, p50 and p95 latency, cost per alert
- red-team detection and block rates, and false flags on benign look-alikes and held-out benign alerts

`eval/thresholds.json` sets the minimum for each. CI and the deploy workflow fail when a metric drops below it.

## Manage

| Risk | Control |
|---|---|
| Prompt injection in alert fields | Pattern scan with flags; `<alert_data>` isolation in the prompt; an injection flag blocks a benign verdict |
| Overconfident benign verdict | Risk model score of 0.8 or higher overrides "benign" to "suspicious" |
| Unsafe or invented actions | Allowlist enforced by the JSON schema and again after parsing |
| Invented citations | Citations not in the retrieved set are removed and flagged |
| Personal data sent to the model | Emails, SSNs, card numbers, and phone numbers redacted before the prompt |
| Model refusal or truncated output | Server-side fallback model; if the response is still a refusal or hits max tokens, the deterministic path answers and the result is flagged |
| Drift | Prometheus counters for verdict mix and guardrail interventions; a shift in either is visible on the Grafana dashboard |
