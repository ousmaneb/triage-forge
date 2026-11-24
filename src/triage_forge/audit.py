"""Append-only audit trail: every verdict and every analyst decision on a held action."""

import json
import threading
from datetime import UTC, datetime
from pathlib import Path

_lock = threading.Lock()


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields) -> None:
        record = {"ts": datetime.now(UTC).isoformat(), "event": event, **fields}
        line = json.dumps(record, sort_keys=True, default=str)
        with _lock, self.path.open("a") as f:
            f.write(line + "\n")

    def read(self, limit: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text().splitlines()[-limit:]
        return [json.loads(line) for line in lines]
