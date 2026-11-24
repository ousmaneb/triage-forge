import json
import time
from contextlib import contextmanager

from . import guardrails
from .config import Settings
from .features import alert_text
from .llm import get_provider
from .models import load
from .observability import GUARDRAIL_FLAGS, LLM_COST, LLM_TOKENS, STAGE_LATENCY, TRIAGE_LATENCY, VERDICTS
from .retrieval import BM25, load_corpus
from .schemas import Alert, TriageResult


@contextmanager
def _stage(name: str):
    start = time.perf_counter()
    yield
    STAGE_LATENCY.labels(name).observe(time.perf_counter() - start)


class Triage:
    def __init__(self, settings: Settings, provider=None):
        self.settings = settings
        self.risk_model, self.technique_model = load(settings.model_dir)
        self.retriever = BM25(load_corpus(settings.data_dir))
        self.techniques = json.loads((settings.data_dir / "techniques.json").read_text())
        self.provider = provider or get_provider(settings)

    def run(self, alert: Alert) -> TriageResult:
        start = time.perf_counter()
        with _stage("risk_model"):
            risk, factors = self.risk_model.score(alert)
        with _stage("technique_model"):
            tid, tconf = self.technique_model.predict(alert)
        tname = self.techniques.get(tid, {}).get("name", tid)
        with _stage("retrieval"):
            hits = self.retriever.search(f"{alert_text(alert)} {tid} {tname}", k=self.settings.retrieval_k)
            chunks = [c for c, _ in hits]
        injection = guardrails.scan_injection(alert)
        with _stage("llm"):
            response = self.provider.triage(alert, risk, factors, (tid, tname, tconf), chunks)
        triage, pending, flags = guardrails.check_output(
            response.triage, risk, {c.id for c in chunks}, injection
        )
        flags = [f"injection:{f}" for f in injection] + list(response.flags) + flags
        latency = time.perf_counter() - start

        TRIAGE_LATENCY.labels(response.provider).observe(latency)
        VERDICTS.labels(triage.verdict.value, alert.source.value).inc()
        for f in flags:
            GUARDRAIL_FLAGS.labels(f.split(":")[0]).inc()
        LLM_TOKENS.labels("input").inc(response.input_tokens)
        LLM_TOKENS.labels("output").inc(response.output_tokens)
        LLM_COST.inc(response.cost_usd)

        return TriageResult(
            alert_id=alert.id,
            verdict=triage.verdict,
            confidence=triage.confidence,
            risk_score=round(risk, 4),
            risk_factors=factors,
            technique_id=tid,
            technique_name=tname,
            technique_confidence=round(tconf, 4),
            summary=triage.summary,
            recommended_actions=triage.recommended_actions,
            pending_approval=pending,
            cited_sources=triage.cited_sources,
            guardrail_flags=flags,
            provider=response.provider,
            latency_ms=round(latency * 1000, 2),
            input_tokens=response.input_tokens,
            output_tokens=response.output_tokens,
            cost_usd=round(response.cost_usd, 6),
        )
