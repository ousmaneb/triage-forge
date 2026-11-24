# Splunk and Microsoft Sentinel

## Splunk

1. Set `SPLUNK_PASSWORD`, `SPLUNK_HEC_TOKEN`, and `TF_WEBHOOK_TOKEN` in `.env`. The token in `ops/splunk/apps/triage_forge/default/savedsearches.conf` (`?token=change-me`) must match `TF_WEBHOOK_TOKEN`.
2. `docker compose --profile splunk up`. The Splunk image is x86_64 only, so on Apple silicon it runs under emulation and takes a few minutes to start. The web UI is at http://localhost:8000.
3. `SPLUNK_HEC_TOKEN=... python scripts/demo.py splunk --count 20` indexes demo events with `sourcetype=triage_forge:demo`.
4. The saved search "Triage Forge - Demo Detections" runs every minute and posts each matching event to `/webhooks/splunk`.
5. Verdicts come back through HEC: `index=main sourcetype="triage_forge:verdict" | table alert_id verdict risk_score technique_id summary`.

Splunk 9.x may require the webhook URL to be on the webhook allow list (Settings > Server settings > Webhook allow list).

Field mapping uses CIM names first (`process`, `dest`, `src`, `user`), then Sysmon (`Image`, `ParentImage`, `CommandLine`, `Computer`), so the same endpoint works for CIM-normalized searches and raw Sysmon.

## Microsoft Sentinel

1. Create a Logic App with the trigger "Microsoft Sentinel incident" and an HTTP action that posts the trigger body to `https://<service>/webhooks/sentinel` with the header `X-Webhook-Token`.
2. Add an automation rule that runs the Logic App when an incident is created.
3. Give the service an Azure AD token with the Microsoft Sentinel Responder role (`SENTINEL_TOKEN`). The verdict is written back as an incident comment through `PUT {incidentId}/comments/{id}?api-version=2024-03-01`.

Without a workspace, `tests/test_service.py::test_sentinel_round_trip` exercises the parser and the comment request against a mocked Azure API, and `scripts/demo.py api` sends Sentinel-shaped incidents to a local service.
