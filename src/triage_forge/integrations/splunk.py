"""Splunk: alerts arrive from the Webhook alert action, verdicts go back through HTTP Event Collector."""

from datetime import UTC, datetime

import httpx

from ..schemas import Alert, Source, TriageResult


def _first(row: dict, *keys: str, default: str = "") -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            return v[0] if isinstance(v, list) else str(v)
    return default


def _int(value: str) -> int:
    try:
        return int(float(value))
    except ValueError:
        return 0


def parse_webhook(payload: dict) -> Alert:
    """Map a Splunk webhook body to an Alert. Field names follow CIM first, then Sysmon."""
    row = payload.get("result") or {}
    ts = _first(row, "_time")
    try:
        timestamp = datetime.fromtimestamp(float(ts), UTC) if ts else datetime.now(UTC)
    except ValueError:
        timestamp = datetime.fromisoformat(ts)
    return Alert(
        id=f"splunk-{payload.get('sid', 'unknown')}",
        source=Source.splunk,
        rule_name=payload.get("search_name", "Splunk alert"),
        timestamp=timestamp,
        host=_first(row, "dest_host", "host", "Computer", default="unknown"),
        user=_first(row, "user", "User", "src_user", default="unknown"),
        process=_first(row, "process_name", "Image").split("\\")[-1],
        parent_process=_first(row, "parent_process_name", "ParentImage").split("\\")[-1],
        command_line=_first(row, "process", "CommandLine", "cmdline"),
        description=_first(row, "signature", "description"),
        src_ip=_first(row, "src_ip", "src"),
        dst_ip=_first(row, "dest_ip", "dest"),
        failed_logins=_int(_first(row, "failure_count", "failed_logins", default="0")),
        bytes_out=_int(_first(row, "bytes_out", default="0")),
        distinct_destinations=_int(_first(row, "dc_dest", "distinct_destinations", default="0")),
        privileged_user=_first(row, "user_priority", "privileged") in ("critical", "high", "true", "1"),
        host_criticality={"critical": 3, "high": 2}.get(_first(row, "dest_priority"), 1),
        geo_mismatch=_first(row, "geo_mismatch") in ("true", "1"),
        raw=row,
    )


class SplunkHEC:
    def __init__(self, url: str, token: str, verify: bool = True, transport: httpx.BaseTransport | None = None):
        self.client = httpx.Client(
            base_url=url, verify=verify, timeout=10, transport=transport,
            headers={"Authorization": f"Splunk {token}"},
        )

    def send_verdict(self, alert: Alert, result: TriageResult) -> None:
        event = {
            "time": datetime.now(UTC).timestamp(),
            "host": alert.host,
            "source": "triage-forge",
            "sourcetype": "triage_forge:verdict",
            "event": result.model_dump(mode="json"),
        }
        response = self.client.post("/services/collector/event", json=event)
        response.raise_for_status()
