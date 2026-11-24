"""Score every part of the triage pipeline on held-out alerts and fail if anything regressed.

    python eval/run_eval.py                      # offline provider, no API cost
    python eval/run_eval.py --provider anthropic --llm-limit 40
    python eval/run_eval.py --gate               # exit 1 if a metric is below eval/thresholds.json
"""

import argparse
import json
import random
import statistics
import sys
from dataclasses import replace
from pathlib import Path

import numpy as np
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from triage_forge import guardrails, synth
from triage_forge.config import get_settings
from triage_forge.features import alert_text, extract
from triage_forge.pipeline import Triage
from triage_forge.retrieval import BM25
from triage_forge.schemas import Verdict

HERE = Path(__file__).parent
HELD_OUT_SEED = 1234


def percentile(values: list[float], q: float) -> float:
    return float(np.percentile(values, q)) if values else 0.0


def evaluate(provider: str, n: int, llm_limit: int) -> dict:
    settings = replace(get_settings(), llm_provider=provider)
    triage = Triage(settings)
    rows = synth.generate(n, seed=HELD_OUT_SEED)

    X = np.stack([extract(a) for a, _, _ in rows])
    y = np.array([label for _, label, _ in rows])
    prob = triage.risk_model.clf.predict_proba(X)[:, 1]
    pred = (prob >= 0.5).astype(int)

    tech_pred = [triage.technique_model.predict(a)[0] for a, _, _ in rows]
    tech_true = [t for _, _, t in rows]

    # Retrieval is scored on the threat reports alone, queried with the alert text only, so it
    # cannot succeed by echoing the classifier's technique id back.
    reports = BM25([c for c in triage.retriever.chunks if not c.id.startswith("technique:")])
    hits = 0
    for alert, _, tid in rows:
        found = reports.search(alert_text(alert), k=settings.retrieval_k)
        hits += any(tid in c.technique for c, _ in found)

    # End-to-end on a sample; with a real LLM this is where the cost is.
    sample = random.Random(0).sample(rows, min(llm_limit, len(rows)))
    e2e_correct, latencies, costs, overrides = 0, [], [], 0
    for alert, label, _ in sample:
        result = triage.run(alert)
        flagged = result.verdict != Verdict.benign
        e2e_correct += int(flagged == bool(label))
        latencies.append(result.latency_ms)
        costs.append(result.cost_usd)
        overrides += any(f.startswith("llm_overruled") for f in result.guardrail_flags)

    attacks = json.loads((HERE / "attacks.json").read_text())
    base = next(a for a, label, t in synth.generate(400, seed=99) if label == 1 and t == "T1059.001")
    blocked, detected = 0, 0
    for case in attacks["cases"]:
        alert = base.model_copy(update={"id": f"redteam-{case['id']}", case["field"]: case["text"]})
        detected += bool(guardrails.scan_injection(alert))
        blocked += triage.run(alert).verdict != Verdict.benign
    false_flags = 0
    for text in attacks["benign_lookalikes"]:
        alert = base.model_copy(update={"command_line": text, "description": "", "rule_name": "Routine activity"})
        false_flags += bool(guardrails.scan_injection(alert))
    benign_held_out = [a for a, label, _ in rows if label == 0]
    false_flags_held_out = sum(bool(guardrails.scan_injection(a)) for a in benign_held_out)

    n_cases = len(attacks["cases"])
    return {
        "provider": triage.provider.name,
        "model": settings.llm_model if provider == "anthropic" else "offline",
        "held_out_alerts": n,
        "risk_model": {
            "roc_auc": round(float(roc_auc_score(y, prob)), 4),
            "precision": round(float(precision_score(y, pred)), 4),
            "recall": round(float(recall_score(y, pred)), 4),
            "f1": round(float(f1_score(y, pred)), 4),
        },
        "technique_accuracy": round(float(np.mean(np.array(tech_pred) == np.array(tech_true))), 4),
        "report_hit_at_k": round(hits / len(rows), 4),
        "end_to_end": {
            "alerts": len(sample),
            "accuracy": round(e2e_correct / len(sample), 4),
            "risk_model_overrides": overrides,
            "latency_ms_p50": round(statistics.median(latencies), 2),
            "latency_ms_p95": round(percentile(latencies, 95), 2),
            "cost_per_alert_usd": round(sum(costs) / len(costs), 6),
        },
        "red_team": {
            "cases": n_cases,
            "detection_rate": round(detected / n_cases, 4),
            "block_rate": round(blocked / n_cases, 4),
            "false_flags_lookalikes": false_flags,
            "false_flag_rate_held_out_benign": round(false_flags_held_out / len(benign_held_out), 4),
        },
    }


def check_gate(results: dict, thresholds: dict) -> list[str]:
    failures = []
    for path, rule in thresholds.items():
        value = results
        for key in path.split("."):
            value = value[key]
        if "min" in rule and value < rule["min"]:
            failures.append(f"{path} = {value} < {rule['min']}")
        if "max" in rule and value > rule["max"]:
            failures.append(f"{path} = {value} > {rule['max']}")
    return failures


def to_markdown(r: dict) -> str:
    rm, e2e, rt = r["risk_model"], r["end_to_end"], r["red_team"]
    return "\n".join([
        f"# Evaluation ({r['provider']}, {r['model']})",
        "",
        f"Held-out alerts: {r['held_out_alerts']} (seed {HELD_OUT_SEED}, never used in training).",
        "",
        "| Component | Metric | Value |",
        "|---|---|---|",
        f"| Risk model | ROC AUC | {rm['roc_auc']} |",
        f"| Risk model | Precision / recall / F1 at 0.5 | {rm['precision']} / {rm['recall']} / {rm['f1']} |",
        f"| Technique classifier | Accuracy (8 techniques) | {r['technique_accuracy']} |",
        f"| Retrieval | Report on the true technique in top k (alert text only) | {r['report_hit_at_k']} |",
        f"| End to end ({e2e['alerts']} alerts) | Verdict accuracy | {e2e['accuracy']} |",
        f"| End to end | Latency p50 / p95 (ms) | {e2e['latency_ms_p50']} / {e2e['latency_ms_p95']} |",
        f"| End to end | Cost per alert (USD) | {e2e['cost_per_alert_usd']} |",
        f"| End to end | Risk-model overrides of a benign LLM verdict | {e2e['risk_model_overrides']} |",
        f"| Red team ({rt['cases']} injection cases) | Detected / blocked "
        f"| {rt['detection_rate']} / {rt['block_rate']} |",
        f"| Red team | False flags on benign look-alikes | {rt['false_flags_lookalikes']} |",
        f"| Red team | False flag rate on held-out benign alerts | {rt['false_flag_rate_held_out_benign']} |",
        "",
    ])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--provider", default="offline", choices=["offline", "anthropic"])
    parser.add_argument("--alerts", type=int, default=2000)
    parser.add_argument("--llm-limit", type=int, default=None,
                        help="alerts sent through the full pipeline (default: 300 offline, 40 with Claude)")
    parser.add_argument("--gate", action="store_true")
    args = parser.parse_args()
    llm_limit = args.llm_limit or (300 if args.provider == "offline" else 40)

    results = evaluate(args.provider, args.alerts, llm_limit)
    suffix = "" if args.provider == "offline" else f"-{args.provider}"
    (HERE / f"results{suffix}.json").write_text(json.dumps(results, indent=2) + "\n")
    (HERE / f"results{suffix}.md").write_text(to_markdown(results))
    print(to_markdown(results))

    if args.gate:
        failures = check_gate(results, json.loads((HERE / "thresholds.json").read_text()))
        if failures:
            print("Gate failed:\n  " + "\n  ".join(failures))
            return 1
        print("Gate passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
