import math
import re

import numpy as np

from .schemas import Alert

_ENCODED = re.compile(r"(-enc(odedcommand)?\s+[A-Za-z0-9+/=]{16,})", re.I)
_DOWNLOAD = re.compile(r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|https?://)", re.I)
_HIDDEN = re.compile(r"(-w(indowstyle)?\s+hidden|-nop\b|bypass)", re.I)
_LSASS = re.compile(r"(lsass|minidump|comsvcs)", re.I)
_RECOVERY = re.compile(r"(delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+no)", re.I)
_REMOTE = re.compile(r"(\\\\[\w.-]+\\|/node:|admin\$)", re.I)
_OFFICE_PARENT = {"winword.exe", "outlook.exe", "excel.exe", "wscript.exe", "mshta.exe"}

# Each feature has a plain-language reason shown to analysts when it pushes risk up.
FEATURES = [
    ("failed_logins_log", "many failed logins"),
    ("bytes_out_log", "large outbound transfer"),
    ("distinct_destinations", "many distinct destinations"),
    ("privileged_user", "privileged account"),
    ("host_criticality", "critical host"),
    ("geo_mismatch", "sign-in from unusual location"),
    ("off_hours", "activity outside business hours"),
    ("encoded_command", "encoded command line"),
    ("download_cradle", "downloads remote content"),
    ("hidden_execution", "hidden or policy-bypass execution"),
    ("office_parent", "spawned by an Office or script host"),
    ("external_src", "external source IP"),
    ("external_dst", "external destination IP"),
    ("lsass_access", "touches LSASS memory"),
    ("recovery_tamper", "deletes shadow copies or recovery"),
    ("remote_exec", "remote execution or admin share"),
    ("cmd_length_log", "unusually long command line"),
]
FEATURE_NAMES = [name for name, _ in FEATURES]
REASONS = dict(FEATURES)


def _external(ip: str) -> bool:
    return bool(ip) and not ip.startswith(("10.", "192.168.", "172.16."))


def extract(alert: Alert) -> np.ndarray:
    cmd = alert.command_line
    hour = alert.timestamp.hour
    values = {
        "failed_logins_log": math.log1p(alert.failed_logins),
        "bytes_out_log": math.log1p(alert.bytes_out) / 3,
        "distinct_destinations": min(alert.distinct_destinations, 100) / 10,
        "privileged_user": float(alert.privileged_user),
        "host_criticality": float(alert.host_criticality),
        "geo_mismatch": float(alert.geo_mismatch),
        "off_hours": float(hour < 6 or hour > 21),
        "encoded_command": float(bool(_ENCODED.search(cmd))),
        "download_cradle": float(bool(_DOWNLOAD.search(cmd))),
        "hidden_execution": float(bool(_HIDDEN.search(cmd))),
        "office_parent": float(alert.parent_process.lower() in _OFFICE_PARENT),
        "external_src": float(_external(alert.src_ip)),
        "external_dst": float(_external(alert.dst_ip)),
        "lsass_access": float(bool(_LSASS.search(cmd))),
        "recovery_tamper": float(bool(_RECOVERY.search(cmd))),
        "remote_exec": float(bool(_REMOTE.search(cmd))),
        "cmd_length_log": math.log1p(len(cmd)),
    }
    return np.array([values[n] for n in FEATURE_NAMES], dtype=float)


def alert_text(alert: Alert) -> str:
    """Text the technique classifier and retriever see."""
    return " ".join(
        part for part in (alert.rule_name, alert.description, alert.process, alert.parent_process, alert.command_line)
        if part
    )
