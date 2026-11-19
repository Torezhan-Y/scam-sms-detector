"""Hybrid scam detector: ML probability + rule-based red flags.

final_score = 0.6 * ml_probability + 0.4 * rules_score
A message is flagged as scam when final_score >= THRESHOLD.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .red_flags import Flag, find_red_flags, rules_score

ML_WEIGHT = 0.6
RULES_WEIGHT = 0.4
THRESHOLD = 0.5
DEFAULT_MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "scam_detector.joblib"


def build_pipeline() -> Pipeline:
    """Character n-grams work for Russian, Kazakh and English at once and
    survive typos and tricks like 'k4spi' or extra spaces."""
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb",
                    ngram_range=(2, 5),
                    lowercase=True,
                    sublinear_tf=True,
                    min_df=2,
                ),
            ),
            ("clf", LogisticRegression(class_weight="balanced", max_iter=2000, C=4.0)),
        ]
    )


@dataclass
class Verdict:
    text: str
    is_scam: bool
    score: float
    ml_probability: float
    rules_score: float
    flags: list[Flag] = field(default_factory=list)

    @property
    def label(self) -> str:
        return "МОШЕННИЧЕСТВО" if self.is_scam else "Похоже на обычное сообщение"


class ScamDetector:
    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline

    @classmethod
    def load(cls, path: Path | str = DEFAULT_MODEL_PATH) -> "ScamDetector":
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Model not found at {path}. Run `python train.py` first.")
        return cls(joblib.load(path))

    def save(self, path: Path | str = DEFAULT_MODEL_PATH) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, path)

    def ml_probability(self, texts: list[str]) -> list[float]:
        scam_index = list(self.pipeline.classes_).index(1)
        return [float(p[scam_index]) for p in self.pipeline.predict_proba(texts)]

    def check(self, text: str) -> Verdict:
        text = text.strip()
        ml = self.ml_probability([text])[0]
        flags = find_red_flags(text)
        rules = rules_score(flags)
        score = round(ML_WEIGHT * ml + RULES_WEIGHT * rules, 4)
        return Verdict(
            text=text,
            is_scam=score >= THRESHOLD,
            score=score,
            ml_probability=round(ml, 4),
            rules_score=rules,
            flags=flags,
        )
