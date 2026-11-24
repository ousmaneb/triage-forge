import hmac
import logging
from collections import OrderedDict

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from pydantic import BaseModel

from .audit import AuditLog
from .config import Settings, get_settings
from .integrations.sentinel import SentinelClient, parse_incident
from .integrations.splunk import SplunkHEC, parse_webhook
from .observability import ERRORS, setup_tracing
from .pipeline import Triage
from .schemas import Alert, TriageResult

log = logging.getLogger("triage_forge")


class Decision(BaseModel):
    action: str
    analyst: str
    approve: bool
    note: str = ""


def create_app(settings: Settings | None = None, provider=None, splunk: SplunkHEC | None = None,
               sentinel: SentinelClient | None = None) -> FastAPI:
    settings = settings or get_settings()
    triage = Triage(settings, provider=provider)
    audit = AuditLog(settings.audit_log)
    if splunk is None and settings.splunk_hec_url:
        splunk = SplunkHEC(settings.splunk_hec_url, settings.splunk_hec_token, settings.splunk_verify_tls)
    if sentinel is None and settings.sentinel_token:
        sentinel = SentinelClient(settings.sentinel_api_url, settings.sentinel_token)
    # Recent results, so held actions can be approved against what the service actually proposed.
    results: OrderedDict[str, TriageResult] = OrderedDict()

    app = FastAPI(title="Triage Forge", version="0.1.0")
    setup_tracing(app)

    def check_token(x_webhook_token: str = Header(default=""), token: str = Query(default="")):
        # Splunk's webhook action cannot set headers, so the token may also come as ?token=.
        if settings.webhook_token and not hmac.compare_digest(x_webhook_token or token, settings.webhook_token):
            raise HTTPException(status_code=401, detail="invalid webhook token")

    def run(alert: Alert) -> TriageResult:
        try:
            result = triage.run(alert)
        except Exception:
            ERRORS.labels("triage").inc()
            log.exception("triage failed for %s", alert.id)
            raise HTTPException(status_code=502, detail="triage failed") from None
        results[alert.id] = result
        while len(results) > 5000:
            results.popitem(last=False)
        audit.write("verdict", alert_id=alert.id, source=alert.source.value, verdict=result.verdict.value,
                    risk=result.risk_score, actions=result.recommended_actions,
                    pending=result.pending_approval, flags=result.guardrail_flags, provider=result.provider)
        return result

    @app.get("/health")
    def health():
        return {"status": "ok", "provider": triage.provider.name, "model": settings.llm_model}

    @app.get("/metrics")
    def metrics():
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    @app.post("/triage", response_model=TriageResult)
    def triage_alert(alert: Alert):
        return run(alert)

    @app.post("/webhooks/splunk", dependencies=[Depends(check_token)])
    def splunk_webhook(payload: dict):
        alert = parse_webhook(payload)
        result = run(alert)
        delivered = None
        if splunk:
            try:
                splunk.send_verdict(alert, result)
                delivered = True
            except Exception:
                ERRORS.labels("splunk_hec").inc()
                log.exception("HEC delivery failed for %s", alert.id)
                delivered = False
        return {"result": result, "delivered_to_splunk": delivered}

    @app.post("/webhooks/sentinel", dependencies=[Depends(check_token)])
    def sentinel_webhook(payload: dict):
        alert = parse_incident(payload)
        result = run(alert)
        delivered = None
        incident_id = alert.raw.get("incidentId")
        if sentinel and incident_id:
            try:
                sentinel.add_comment(incident_id, result)
                delivered = True
            except Exception:
                ERRORS.labels("sentinel").inc()
                log.exception("Sentinel comment failed for %s", alert.id)
                delivered = False
        return {"result": result, "delivered_to_sentinel": delivered}

    @app.post("/alerts/{alert_id}/decisions")
    def decide(alert_id: str, decision: Decision):
        result = results.get(alert_id)
        if result is None:
            raise HTTPException(status_code=404, detail="unknown alert")
        if decision.action not in result.pending_approval:
            raise HTTPException(status_code=409, detail="action is not awaiting approval")
        result.pending_approval.remove(decision.action)
        audit.write("action_decision", alert_id=alert_id, action=decision.action, analyst=decision.analyst,
                    approved=decision.approve, note=decision.note)
        # Execution belongs to the SOAR platform; this service records the human decision.
        return {"alert_id": alert_id, "action": decision.action, "approved": decision.approve,
                "still_pending": result.pending_approval}

    @app.get("/audit")
    def audit_log(limit: int = 100):
        return audit.read(limit)

    return app
