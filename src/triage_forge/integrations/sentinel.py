"""Microsoft Sentinel: incidents arrive from an automation rule's Logic App, verdicts go back as incident comments."""

import uuid
from datetime import UTC, datetime

import httpx

from ..schemas import Alert, Source, TriageResult

API_VERSION = "2024-03-01"


def _entities(props: dict, kind: str) -> list[dict]:
    return [e.get("properties", {}) for e in props.get("relatedEntities", []) if e.get("kind") == kind]


def parse_incident(payload: dict) -> Alert:
    """Map the Logic App 'Microsoft Sentinel incident' trigger body to an Alert."""
    obj = payload.get("object", payload)
    props = obj.get("properties", {})
    hosts = _entities(props, "Host")
    accounts = _entities(props, "Account")
    processes = _entities(props, "Process")
    ips = _entities(props, "Ip")
    extra = props.get("additionalData", {})
    proc = processes[0] if processes else {}
    created = props.get("createdTimeUtc")
    return Alert(
        id=f"sentinel-{props.get('incidentNumber', obj.get('name', 'unknown'))}",
        source=Source.sentinel,
        rule_name=props.get("title", "Sentinel incident"),
        timestamp=datetime.fromisoformat(created.replace("Z", "+00:00")) if created else datetime.now(UTC),
        host=hosts[0].get("hostName", "unknown") if hosts else "unknown",
        user=accounts[0].get("accountName", "unknown") if accounts else "unknown",
        process=proc.get("imageFile", {}).get("fileName", "") if isinstance(proc.get("imageFile"), dict) else "",
        parent_process=(proc.get("parentProcess") or {}).get("imageFile", {}).get("fileName", ""),
        command_line=proc.get("commandLine", ""),
        description=props.get("description", ""),
        src_ip=ips[0].get("address", "") if ips else "",
        dst_ip=ips[1].get("address", "") if len(ips) > 1 else "",
        failed_logins=int(extra.get("failedLogins", 0)),
        bytes_out=int(extra.get("bytesOut", 0)),
        distinct_destinations=int(extra.get("distinctDestinations", 0)),
        privileged_user=bool(extra.get("privileged", False)),
        host_criticality={"High": 3, "Medium": 2}.get(props.get("severity", ""), 1),
        geo_mismatch=bool(extra.get("geoMismatch", False)),
        raw={"incidentId": obj.get("id", ""), "severity": props.get("severity", "")},
    )


def format_comment(result: TriageResult) -> str:
    lines = [
        f"Triage Forge verdict: {result.verdict.value.upper()} (confidence {result.confidence:.2f}, "
        f"risk {result.risk_score:.2f})",
        f"Technique: {result.technique_id} {result.technique_name}",
        result.summary,
        f"Recommended: {', '.join(result.recommended_actions) or 'none'}",
    ]
    if result.pending_approval:
        lines.append(f"Awaiting analyst approval: {', '.join(result.pending_approval)}")
    if result.guardrail_flags:
        lines.append(f"Guardrail flags: {', '.join(result.guardrail_flags)}")
    return "\n".join(lines)


class SentinelClient:
    def __init__(self, api_url: str, token: str, transport: httpx.BaseTransport | None = None):
        self.client = httpx.Client(
            base_url=api_url or "https://management.azure.com", timeout=10, transport=transport,
            headers={"Authorization": f"Bearer {token}"},
        )

    def add_comment(self, incident_id: str, result: TriageResult) -> None:
        url = f"{incident_id}/comments/{uuid.uuid4()}"
        response = self.client.put(
            url, params={"api-version": API_VERSION}, json={"properties": {"message": format_comment(result)}}
        )
        response.raise_for_status()
