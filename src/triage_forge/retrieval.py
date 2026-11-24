"""BM25 retrieval over threat reports and technique notes.

BM25 rather than embeddings: alert text is full of exact tokens (comsvcs.dll, -enc, ADMIN$)
that lexical matching handles well, and it keeps the service free of a model download.
"""

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_TOKEN = re.compile(r"[a-z0-9][a-z0-9._$-]*")


def tokenize(text: str) -> list[str]:
    return [t.strip(".") for t in _TOKEN.findall(text.lower()) if len(t.strip(".")) > 1]


@dataclass
class Chunk:
    id: str
    text: str
    technique: str = ""  # comma-separated ATT&CK ids the chunk covers


def load_corpus(data_dir: Path) -> list[Chunk]:
    chunks = []
    techniques = json.loads((data_dir / "techniques.json").read_text())
    for tid, info in techniques.items():
        chunks.append(Chunk(id=f"technique:{tid}", text=f"{tid} {info['name']}. {info['triage']}", technique=tid))
    for path in sorted((data_dir / "reports").glob("*.md")):
        report_id = path.stem.split("-")[0].upper() + "-" + "-".join(path.stem.split("-")[1:3])
        paragraphs = [p.strip() for p in path.read_text().split("\n\n") if p.strip() and not p.startswith("# ")]
        tags = next((p.removeprefix("ATT&CK:").strip() for p in paragraphs if p.startswith("ATT&CK:")), "")
        body = [p for p in paragraphs if not p.startswith("ATT&CK:")]
        for i, para in enumerate(body, 1):
            chunks.append(Chunk(id=f"{report_id}#{i}", text=para, technique=tags))
    return chunks


class BM25:
    def __init__(self, chunks: list[Chunk], k1: float = 1.4, b: float = 0.75):
        self.chunks = chunks
        self.k1, self.b = k1, b
        self.docs = [Counter(tokenize(c.text)) for c in chunks]
        self.lengths = [sum(d.values()) for d in self.docs]
        self.avg_len = sum(self.lengths) / len(self.lengths)
        df = Counter(term for d in self.docs for term in d)
        n = len(self.docs)
        self.idf = {t: math.log(1 + (n - f + 0.5) / (f + 0.5)) for t, f in df.items()}

    def search(self, query: str, k: int = 3) -> list[tuple[Chunk, float]]:
        terms = tokenize(query)
        scores = []
        for i, doc in enumerate(self.docs):
            s = 0.0
            norm = self.k1 * (1 - self.b + self.b * self.lengths[i] / self.avg_len)
            for t in terms:
                f = doc.get(t)
                if f:
                    s += self.idf[t] * f * (self.k1 + 1) / (f + norm)
            if s > 0:
                scores.append((self.chunks[i], s))
        scores.sort(key=lambda x: -x[1])
        return scores[:k]
