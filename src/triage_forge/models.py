"""Risk model (is this alert malicious?) and technique classifier (which ATT&CK technique?)."""

from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline

from . import synth
from .features import FEATURE_NAMES, REASONS, alert_text, extract
from .schemas import Alert

RISK_FILE = "risk_model.joblib"
TECHNIQUE_FILE = "technique_model.joblib"


@dataclass
class RiskModel:
    clf: HistGradientBoostingClassifier
    importance: np.ndarray
    high_marks: np.ndarray  # per-feature 75th percentile on training data
    binary: np.ndarray  # True where the feature only takes 0 or 1

    def score(self, alert: Alert) -> tuple[float, list[str]]:
        x = extract(alert)
        prob = float(self.clf.predict_proba(x.reshape(1, -1))[0, 1])
        return prob, self.reasons(x)

    def reasons(self, x: np.ndarray, limit: int = 4) -> list[str]:
        # A feature is cited when it is set (binary) or above the training 75th percentile,
        # ordered by how much the model relies on it overall.
        hits = [
            i for i, v in enumerate(x)
            if (v == 1 if self.binary[i] else v > 0 and v >= self.high_marks[i])
        ]
        hits.sort(key=lambda i: -self.importance[i])
        return [REASONS[FEATURE_NAMES[i]] for i in hits if self.importance[i] > 0][:limit]


@dataclass
class TechniqueModel:
    pipe: object

    def predict(self, alert: Alert) -> tuple[str, float]:
        proba = self.pipe.predict_proba([alert_text(alert)])[0]
        i = int(np.argmax(proba))
        return str(self.pipe.classes_[i]), float(proba[i])


def train(n: int = 6000, seed: int = 7) -> tuple[RiskModel, TechniqueModel]:
    rows = synth.generate(n, seed=seed)
    X = np.stack([extract(a) for a, _, _ in rows])
    y = np.array([label for _, label, _ in rows])
    clf = HistGradientBoostingClassifier(max_iter=200, learning_rate=0.08, max_leaf_nodes=24, random_state=seed)
    clf.fit(X, y)
    imp = permutation_importance(clf, X, y, n_repeats=5, random_state=seed, scoring="roc_auc").importances_mean
    risk = RiskModel(
        clf=clf,
        importance=np.clip(imp, 0, None),
        high_marks=np.percentile(X, 75, axis=0),
        binary=np.array([set(np.unique(col)) <= {0.0, 1.0} for col in X.T]),
    )

    texts = [alert_text(a) for a, _, _ in rows]
    techniques = [t for _, _, t in rows]
    pipe = make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=2, sublinear_tf=True),
        LogisticRegression(max_iter=2000, C=4.0),
    )
    pipe.fit(texts, techniques)
    return risk, TechniqueModel(pipe=pipe)


def save(risk: RiskModel, technique: TechniqueModel, model_dir: Path) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(risk, model_dir / RISK_FILE)
    joblib.dump(technique, model_dir / TECHNIQUE_FILE)


def load(model_dir: Path) -> tuple[RiskModel, TechniqueModel]:
    if not (model_dir / RISK_FILE).exists():
        risk, technique = train()
        save(risk, technique, model_dir)
        return risk, technique
    return joblib.load(model_dir / RISK_FILE), joblib.load(model_dir / TECHNIQUE_FILE)
