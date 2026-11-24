import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from triage_forge.api import create_app
from triage_forge.integrations.sentinel import SentinelClient
from triage_forge.integrations.splunk import SplunkHEC
from triage_forge.llm import ClaudeProvider, OfflineProvider
from triage_forge.pipeline import Triage
from triage_forge.schemas import Verdict


@pytest.fixture(scope="module")
def triage(settings):
    return Triage(settings, provider=OfflineProvider())


def test_pipeline_malicious(triage, malicious_alert):
    result = triage.run(malicious_alert)
    assert result.verdict == Verdict.malicious
    assert result.technique_id == "T1059.001"
    assert "isolate_host" in result.pending_approval
    assert result.cited_sources


def test_pipeline_benign(triage, benign_alert):
    assert triage.run(benign_alert).verdict == Verdict.benign


SPLUNK_PAYLOAD = {
    "sid": "scheduler__admin__search__RMD5a1",
    "search_name": "LSASS Memory Access",
    "result": {
        "_time": "1767240000",
        "host": "sql-prod-01",
        "user": "adm_rpatel",
        "Image": "C:\\Windows\\System32\\rundll32.exe",
        "ParentImage": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full",
        "dest_priority": "critical",
    },
}

SENTINEL_PAYLOAD = {
    "object": {
        "id": "/subscriptions/0000/resourceGroups/soc/providers/Microsoft.OperationalInsights/workspaces/w"
              "/providers/Microsoft.SecurityInsights/Incidents/abc",
        "properties": {
            "incidentNumber": 4211,
            "title": "Shadow Copy Deletion",
            "severity": "High",
            "createdTimeUtc": "2026-02-11T03:12:00Z",
            "description": "Command that touches shadow copies",
            "relatedEntities": [
                {"kind": "Host", "properties": {"hostName": "fs-02"}},
                {"kind": "Account", "properties": {"accountName": "bwhite"}},
                {"kind": "Process", "properties": {
                    "commandLine": "vssadmin.exe delete shadows /all /quiet",
                    "imageFile": {"fileName": "vssadmin.exe"},
                    "parentProcess": {"imageFile": {"fileName": "cmd.exe"}},
                }},
            ],
        },
    }
}


@pytest.fixture
def captured():
    return []


@pytest.fixture
def client(settings, captured):
    def handler(request: httpx.Request):
        captured.append(request)
        return httpx.Response(200, json={"text": "Success", "code": 0})

    transport = httpx.MockTransport(handler)
    app = create_app(
        settings,
        provider=OfflineProvider(),
        splunk=SplunkHEC("https://splunk.test:8088", "hec-token", transport=transport),
        sentinel=SentinelClient("https://management.azure.test", "aad-token", transport=transport),
    )
    return TestClient(app)


def test_health_and_metrics(client):
    assert client.get("/health").json()["status"] == "ok"
    client.post("/webhooks/splunk", json=SPLUNK_PAYLOAD)
    assert "tf_verdicts_total" in client.get("/metrics").text


def test_splunk_round_trip(client, captured):
    body = client.post("/webhooks/splunk", json=SPLUNK_PAYLOAD).json()
    assert body["delivered_to_splunk"] is True
    assert body["result"]["technique_id"] == "T1003.001"
    hec = captured[-1]
    assert hec.url.path == "/services/collector/event"
    assert hec.headers["Authorization"] == "Splunk hec-token"
    assert json.loads(hec.content)["sourcetype"] == "triage_forge:verdict"


def test_sentinel_round_trip(client, captured):
    body = client.post("/webhooks/sentinel", json=SENTINEL_PAYLOAD).json()
    assert body["delivered_to_sentinel"] is True
    assert body["result"]["technique_id"] == "T1490"
    put = captured[-1]
    assert put.method == "PUT" and "/Incidents/abc/comments/" in put.url.path
    assert "Triage Forge verdict" in json.loads(put.content)["properties"]["message"]


def test_webhook_token_required(settings):
    from dataclasses import replace

    app = create_app(replace(settings, webhook_token="s3cret"), provider=OfflineProvider())
    c = TestClient(app)
    assert c.post("/webhooks/splunk", json=SPLUNK_PAYLOAD).status_code == 401
    assert c.post("/webhooks/splunk?token=s3cret", json=SPLUNK_PAYLOAD).status_code == 200


def test_held_action_needs_decision(client, malicious_alert):
    result = client.post("/triage", json=malicious_alert.model_dump(mode="json")).json()
    assert "isolate_host" in result["pending_approval"]
    url = f"/alerts/{malicious_alert.id}/decisions"
    assert client.post(url, json={"action": "wipe_disk", "analyst": "a", "approve": True}).status_code == 409
    ok = client.post(url, json={"action": "isolate_host", "analyst": "akumar", "approve": True}).json()
    assert ok["approved"] is True and "isolate_host" not in ok["still_pending"]
    events = [e["event"] for e in client.get("/audit").json()]
    assert "verdict" in events and "action_decision" in events


class FakeMessages:
    def __init__(self, response):
        self.response = response
        self.kwargs = None

    def create(self, **kwargs):
        self.kwargs = kwargs
        return self.response


def _fake_client(text: str, stop_reason: str = "end_turn"):
    usage = SimpleNamespace(input_tokens=900, output_tokens=150, cache_read_input_tokens=1200,
                            cache_creation_input_tokens=0)
    response = SimpleNamespace(stop_reason=stop_reason, usage=usage,
                               content=[SimpleNamespace(type="text", text=text)])
    messages = FakeMessages(response)
    return SimpleNamespace(beta=SimpleNamespace(messages=messages)), messages


def test_claude_provider_request_and_parse(settings, malicious_alert):
    answer = json.dumps({
        "verdict": "malicious", "confidence": 0.93, "summary": "Encoded PowerShell from Word.",
        "technique_id": "T1059.001", "recommended_actions": ["isolate_host", "open_ticket"],
        "cited_sources": ["TR-2026-001#1"],
    })
    fake, messages = _fake_client(answer)
    triage = Triage(settings, provider=ClaudeProvider(settings, client=fake))
    result = triage.run(malicious_alert)

    sent = messages.kwargs
    assert sent["model"] == settings.llm_model
    assert sent["output_config"]["format"]["type"] == "json_schema"
    assert sent["fallbacks"] == "default"
    assert "<alert_data>" in sent["messages"][0]["content"]
    assert result.provider == "anthropic"
    assert result.verdict == Verdict.malicious
    assert result.cost_usd > 0


def test_claude_refusal_falls_back(settings, malicious_alert):
    fake, _ = _fake_client("", stop_reason="refusal")
    result = Triage(settings, provider=ClaudeProvider(settings, client=fake)).run(malicious_alert)
    assert result.provider == "anthropic->offline"
    assert "llm_refusal" in result.guardrail_flags
