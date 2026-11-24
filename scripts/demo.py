"""Send synthetic alerts through the system.

    python scripts/demo.py api --count 20            # post Splunk- and Sentinel-style webhooks to the API
    python scripts/demo.py splunk --count 20         # index events in Splunk; the saved search forwards them
"""

import argparse
import os
import random

import httpx

from triage_forge import synth


def splunk_row(alert) -> dict:
    return {
        "_time": str(alert.timestamp.timestamp()),
        "host": alert.host,
        "user": alert.user,
        "Image": f"C:\\Windows\\System32\\{alert.process}" if alert.process else "",
        "ParentImage": f"C:\\Windows\\System32\\{alert.parent_process}" if alert.parent_process else "",
        "CommandLine": alert.command_line,
        "signature": alert.description,
        "src_ip": alert.src_ip,
        "dest_ip": alert.dst_ip,
        "failure_count": str(alert.failed_logins),
        "bytes_out": str(alert.bytes_out),
        "dc_dest": str(alert.distinct_destinations),
        "dest_priority": {3: "critical", 2: "high"}.get(alert.host_criticality, "medium"),
        "user_priority": "high" if alert.privileged_user else "low",
        "geo_mismatch": str(alert.geo_mismatch).lower(),
    }


def sentinel_incident(alert, number: int) -> dict:
    entities = [
        {"kind": "Host", "properties": {"hostName": alert.host}},
        {"kind": "Account", "properties": {"accountName": alert.user}},
    ]
    if alert.process:
        entities.append({"kind": "Process", "properties": {
            "commandLine": alert.command_line,
            "imageFile": {"fileName": alert.process},
            "parentProcess": {"imageFile": {"fileName": alert.parent_process}},
        }})
    if alert.src_ip:
        entities.append({"kind": "Ip", "properties": {"address": alert.src_ip}})
    return {"object": {"id": f"/demo/Incidents/{number}", "properties": {
        "incidentNumber": number,
        "title": alert.rule_name,
        "description": alert.description,
        "severity": {3: "High", 2: "Medium"}.get(alert.host_criticality, "Low"),
        "createdTimeUtc": alert.timestamp.isoformat().replace("+00:00", "Z"),
        "relatedEntities": entities,
        "additionalData": {"failedLogins": alert.failed_logins, "bytesOut": alert.bytes_out,
                           "distinctDestinations": alert.distinct_destinations,
                           "privileged": alert.privileged_user, "geoMismatch": alert.geo_mismatch},
    }}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("target", choices=["api", "splunk"])
    parser.add_argument("--count", type=int, default=10)
    parser.add_argument("--api", default="http://localhost:8080")
    parser.add_argument("--hec", default="https://localhost:8088")
    args = parser.parse_args()

    rows = synth.generate(args.count, seed=random.randint(0, 10**6))
    if args.target == "api":
        token = os.environ.get("TF_WEBHOOK_TOKEN", "")
        with httpx.Client(base_url=args.api, timeout=120, headers={"X-Webhook-Token": token}) as client:
            for i, (alert, label, _) in enumerate(rows):
                if i % 2:
                    body = client.post("/webhooks/sentinel", json=sentinel_incident(alert, 5000 + i)).json()
                else:
                    body = client.post("/webhooks/splunk", json={
                        "sid": f"demo-{i}", "search_name": alert.rule_name, "result": splunk_row(alert),
                    }).json()
                r = body["result"]
                truth = "malicious" if label else "benign"
                print(f"{r['verdict']:<10} truth={truth:<9} risk={r['risk_score']:.2f} {r['technique_id']:<10} "
                      f"{r['latency_ms']:>8.0f} ms  ${r['cost_usd']:.4f}  {alert.rule_name}")
    else:
        token = os.environ["SPLUNK_HEC_TOKEN"]
        with httpx.Client(base_url=args.hec, verify=False, headers={"Authorization": f"Splunk {token}"}) as client:
            for alert, _, _ in rows:
                event = {"sourcetype": "triage_forge:demo", "host": alert.host, "event": splunk_row(alert)}
                client.post("/services/collector/event", json=event).raise_for_status()
        print(f"Indexed {len(rows)} events; the saved search forwards them within a minute.")


if __name__ == "__main__":
    main()
