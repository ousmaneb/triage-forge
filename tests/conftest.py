from dataclasses import replace
from datetime import UTC, datetime

import pytest

from triage_forge.config import get_settings
from triage_forge.schemas import Alert


@pytest.fixture(scope="session")
def settings(tmp_path_factory):
    return replace(
        get_settings(),
        llm_provider="offline",
        audit_log=tmp_path_factory.mktemp("audit") / "audit.jsonl",
        webhook_token="",
    )


@pytest.fixture
def malicious_alert():
    return Alert(
        id="t-mal-1",
        rule_name="Suspicious PowerShell Execution",
        timestamp=datetime(2026, 3, 2, 2, 14, tzinfo=UTC),
        host="fin-ws-12",
        user="adm_jsmith",
        privileged_user=True,
        process="powershell.exe",
        parent_process="winword.exe",
        command_line="powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=",
        description="PowerShell launched with obfuscated arguments",
    )


@pytest.fixture
def benign_alert():
    return Alert(
        id="t-ben-1",
        rule_name="Scheduled Task Created",
        timestamp=datetime(2026, 3, 2, 10, 5, tzinfo=UTC),
        host="fin-ws-03",
        user="svc_deploy",
        process="schtasks.exe",
        parent_process="ccmexec.exe",
        command_line='schtasks /create /sc daily /tn "DiskCleanup" /tr "C:\\IT\\cleanup.cmd"',
        description="A new scheduled task was registered",
    )
