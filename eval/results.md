# Evaluation (offline, offline)

Held-out alerts: 2000 (seed 1234, never used in training).

| Component | Metric | Value |
|---|---|---|
| Risk model | ROC AUC | 0.9454 |
| Risk model | Precision / recall / F1 at 0.5 | 0.9521 / 0.9047 / 0.9278 |
| Technique classifier | Accuracy (8 techniques) | 0.959 |
| Retrieval | Report on the true technique in top k (alert text only) | 0.855 |
| End to end (300 alerts) | Verdict accuracy | 0.95 |
| End to end | Latency p50 / p95 (ms) | 8.37 / 11.82 |
| End to end | Cost per alert (USD) | 0.0 |
| End to end | Risk-model overrides of a benign LLM verdict | 0 |
| Red team (10 injection cases) | Detected / blocked | 1.0 / 1.0 |
| Red team | False flags on benign look-alikes | 0 |
| Red team | False flag rate on held-out benign alerts | 0.0 |
