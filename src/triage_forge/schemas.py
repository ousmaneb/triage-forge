from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class Source(StrEnum):
    splunk = "splunk"
    sentinel = "sentinel"
    api = "api"


class Alert(BaseModel):
    """One alert, normalized from whichever SIEM sent it.

    Structured fields feed the risk model; free-text fields (command_line, description,
    raw) are attacker-influenced and are treated as untrusted when shown to the LLM.
    """

    id: str
    source: Source = Source.api
    rule_name: str
    timestamp: datetime
    host: str
    user: str
    process: str = ""
    parent_process: str = ""
    command_line: str = ""
    description: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    failed_logins: int = 0
    bytes_out: int = 0
    distinct_destinations: int = 0
    privileged_user: bool = False
    host_criticality: int = Field(default=1, ge=1, le=3)
    geo_mismatch: bool = False
    raw: dict = Field(default_factory=dict)


class Verdict(StrEnum):
    malicious = "malicious"
    suspicious = "suspicious"
    benign = "benign"


# Actions the service may propose. Anything that changes a system needs analyst approval.
CONTAINMENT_ACTIONS = {"isolate_host", "disable_account", "block_ip", "kill_process"}
SAFE_ACTIONS = {"open_ticket", "collect_forensics", "notify_owner", "monitor", "close_as_benign"}
ALLOWED_ACTIONS = CONTAINMENT_ACTIONS | SAFE_ACTIONS


class LLMTriage(BaseModel):
    verdict: Verdict
    confidence: float = Field(ge=0, le=1)
    summary: str
    technique_id: str
    recommended_actions: list[str]
    cited_sources: list[str]


class TriageResult(BaseModel):
    alert_id: str
    verdict: Verdict
    confidence: float
    risk_score: float
    risk_factors: list[str]
    technique_id: str
    technique_name: str
    technique_confidence: float
    summary: str
    recommended_actions: list[str]
    pending_approval: list[str]
    cited_sources: list[str]
    guardrail_flags: list[str]
    provider: str
    latency_ms: float
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
