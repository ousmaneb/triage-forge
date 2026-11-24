import json
from pathlib import Path

from triage_forge import guardrails
from triage_forge.features import FEATURE_NAMES, extract
from triage_forge.retrieval import BM25, load_corpus, tokenize
from triage_forge.schemas import LLMTriage, Verdict

ATTACKS = json.loads((Path(__file__).parents[1] / "eval" / "attacks.json").read_text())


def test_features_flag_encoded_download_and_office_parent(malicious_alert):
    x = dict(zip(FEATURE_NAMES, extract(malicious_alert), strict=True))
    assert x["encoded_command"] == 1
    assert x["hidden_execution"] == 1
    assert x["office_parent"] == 1
    assert x["off_hours"] == 1


def test_tokenize_keeps_security_tokens():
    assert {"comsvcs.dll", "admin$", "enc"} <= set(tokenize("rundll32 comsvcs.dll ADMIN$ -enc"))


def test_bm25_finds_lsass_report(settings):
    hits = BM25(load_corpus(settings.data_dir)).search("rundll32 comsvcs.dll MiniDump lsass", k=3)
    assert any(c.id.startswith("TR-2026-003") or c.technique == "T1003.001" for c, _ in hits)


def test_every_attack_is_detected(malicious_alert):
    for case in ATTACKS["cases"]:
        alert = malicious_alert.model_copy(update={case["field"]: case["text"]})
        assert guardrails.scan_injection(alert), case["id"]


def test_lookalikes_are_not_flagged(benign_alert):
    for text in ATTACKS["benign_lookalikes"]:
        assert not guardrails.scan_injection(benign_alert.model_copy(update={"command_line": text})), text


def test_redact_removes_pii():
    out = guardrails.redact("mail jane.doe@corp.com ssn 123-45-6789 card 4111 1111 1111 1111")
    assert "jane.doe" not in out and "123-45-6789" not in out and "4111" not in out


def _llm(**kw):
    base = dict(verdict=Verdict.benign, confidence=0.9, summary="s", technique_id="T1059.001",
                recommended_actions=["close_as_benign"], cited_sources=["TR-2026-001#1"])
    return LLMTriage(**{**base, **kw})


def test_risk_model_overrules_benign_llm_verdict():
    triage, pending, flags = guardrails.check_output(_llm(), 0.93, {"TR-2026-001#1"}, [])
    assert triage.verdict == Verdict.suspicious
    assert "close_as_benign" not in triage.recommended_actions
    assert "llm_overruled_by_risk_model" in flags


def test_containment_is_held_and_unknown_actions_dropped():
    llm = _llm(verdict=Verdict.malicious, recommended_actions=["isolate_host", "wipe_disk", "open_ticket"],
               cited_sources=["TR-2026-001#1", "made-up"])
    triage, pending, flags = guardrails.check_output(llm, 0.95, {"TR-2026-001#1"}, [])
    assert pending == ["isolate_host"]
    assert "wipe_disk" not in triage.recommended_actions
    assert triage.cited_sources == ["TR-2026-001#1"]
    assert {"unknown_action_removed", "uncited_source_removed"} <= set(flags)


def test_injection_blocks_benign_even_at_low_risk():
    triage, _, flags = guardrails.check_output(_llm(), 0.1, set(), ["verdict_steering"])
    assert triage.verdict == Verdict.suspicious
    assert "injection_blocks_benign_verdict" in flags
