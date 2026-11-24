import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("TF_DATA_DIR", str(ROOT / "data"))))
    model_dir: Path = field(default_factory=lambda: Path(_env("TF_MODEL_DIR", str(ROOT / "models"))))
    audit_log: Path = field(default_factory=lambda: Path(_env("TF_AUDIT_LOG", str(ROOT / "audit" / "audit.jsonl"))))

    # "anthropic" uses Claude; "offline" is deterministic and needs no key (tests, CI, demos).
    llm_provider: str = field(default_factory=lambda: _env("TF_LLM_PROVIDER", "anthropic"))
    llm_model: str = field(default_factory=lambda: _env("TF_LLM_MODEL", "claude-opus-5-5"))
    llm_effort: str = field(default_factory=lambda: _env("TF_LLM_EFFORT", "medium"))
    # USD per million tokens; override when changing models.
    price_in: float = field(default_factory=lambda: float(_env("TF_PRICE_IN", "4.0")))
    price_out: float = field(default_factory=lambda: float(_env("TF_PRICE_OUT", "20.0")))

    retrieval_k: int = field(default_factory=lambda: int(_env("TF_RETRIEVAL_K", "3")))

    splunk_hec_url: str = field(default_factory=lambda: _env("SPLUNK_HEC_URL"))
    splunk_hec_token: str = field(default_factory=lambda: _env("SPLUNK_HEC_TOKEN"))
    splunk_verify_tls: bool = field(default_factory=lambda: _env("SPLUNK_VERIFY_TLS", "true") == "true")
    sentinel_api_url: str = field(default_factory=lambda: _env("SENTINEL_API_URL"))
    sentinel_token: str = field(default_factory=lambda: _env("SENTINEL_TOKEN"))

    # Shared secret the SIEM webhooks must send; empty disables the check for local runs.
    webhook_token: str = field(default_factory=lambda: _env("TF_WEBHOOK_TOKEN"))


def get_settings() -> Settings:
    return Settings()
