"""Guardrails around the LLM.

Alert fields such as command lines, file names and email subjects are written by whoever
triggered the alert, which may be the attacker. They are scanned for instructions aimed at
the model, wrapped as untrusted data in the prompt, and never allowed to lower the verdict
below what the risk model supports.
"""

import re

from .schemas import ALLOWED_ACTIONS, CONTAINMENT_ACTIONS, Alert, LLMTriage, Verdict

_INJECTION = [
    (re.compile(r"\b(ignore|disregard|forget)\b.{0,40}\b(instructions|rules|prompt|above|previous)\b", re.I),
     "override_instructions"),
    (re.compile(r"\b(you are now|act as|pretend to be|new role)\b", re.I), "role_change"),
    (re.compile(r"\b(system prompt|developer message|hidden instructions)\b", re.I), "prompt_probe"),
    (re.compile(r"\b(mark|classify|label|treat|report)\b.{0,30}\b(benign|safe|false positive|harmless)\b", re.I),
     "verdict_steering"),
    (re.compile(r"\b(do not|don't|never)\b.{0,20}\b(escalate|alert|report|isolate)\b", re.I), "suppress_response"),
    (re.compile(r"</?\s*(untrusted|system|assistant|instructions)\s*>|\[/?INST\]|<\|im_(start|end)\|>", re.I),
     "delimiter_injection"),
    (re.compile(r"\b(close|resolve|dismiss)\b.{0,20}\b(this|the)\b.{0,10}\b(alert|incident|ticket)\b", re.I),
     "close_request"),
]

_PII = [
    (re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b"), "[EMAIL]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:\d[ -]?){13,16}\b"), "[CARD]"),
    (re.compile(r"\b\(?\d{3}\)?[ .-]\d{3}[ .-]\d{4}\b"), "[PHONE]"),
]

UNTRUSTED_FIELDS = ("rule_name", "description", "process", "parent_process", "command_line", "user", "host")


def _untrusted_text(alert: Alert) -> str:
    parts = [str(getattr(alert, f)) for f in UNTRUSTED_FIELDS]
    parts += [str(v) for v in alert.raw.values() if isinstance(v, str)]
    return "\n".join(parts)


def scan_injection(alert: Alert) -> list[str]:
    text = _untrusted_text(alert)
    return sorted({name for pattern, name in _INJECTION if pattern.search(text)})


def redact(text: str) -> str:
    for pattern, placeholder in _PII:
        text = pattern.sub(placeholder, text)
    return text


def check_output(
    llm: LLMTriage, risk_score: float, retrieved_ids: set[str], injection_flags: list[str]
) -> tuple[LLMTriage, list[str], list[str]]:
    """Return the corrected triage, actions held for approval, and guardrail flags."""
    flags = []

    actions = [a for a in llm.recommended_actions if a in ALLOWED_ACTIONS]
    if len(actions) != len(llm.recommended_actions):
        flags.append("unknown_action_removed")

    cited = [s for s in llm.cited_sources if s in retrieved_ids]
    if len(cited) != len(llm.cited_sources):
        flags.append("uncited_source_removed")

    verdict = llm.verdict
    # The LLM may raise severity on its own, but lowering it below the risk model needs a human.
    if risk_score >= 0.8 and verdict == Verdict.benign:
        verdict = Verdict.suspicious
        flags.append("llm_overruled_by_risk_model")
    if injection_flags and verdict == Verdict.benign:
        verdict = Verdict.suspicious
        flags.append("injection_blocks_benign_verdict")
    if verdict != Verdict.benign and "close_as_benign" in actions:
        actions.remove("close_as_benign")

    pending = [a for a in actions if a in CONTAINMENT_ACTIONS]
    corrected = llm.model_copy(update={"verdict": verdict, "recommended_actions": actions, "cited_sources": cited})
    return corrected, pending, flags
