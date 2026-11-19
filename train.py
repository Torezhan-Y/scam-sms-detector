"""Train the scam SMS detector and report honest test metrics.

Data:
  * data/sms_spam_uci.tsv      — public SMS Spam Collection (English, real messages)
  * data/ru_kz_synthetic.csv   — synthetic Russian/Kazakh messages (see data/generate_ru_kz.py)

Evaluation split:
  * English: random stratified 20% hold-out.
  * Russian/Kazakh: split BY TEMPLATE, so the test set contains only scam
    schemes and message types the model has never seen. This is much harder
    (and more honest) than a random split of near-identical messages.

After evaluation the final model is re-trained on all data and saved to models/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

from src.detector.model import RULES_WEIGHT, ML_WEIGHT, THRESHOLD, ScamDetector, build_pipeline
from src.detector.red_flags import find_red_flags, rules_score

ROOT = Path(__file__).resolve().parent
SEED = 42


def load_data() -> tuple[pd.DataFrame, pd.DataFrame]:
    en = pd.read_csv(ROOT / "data" / "sms_spam_uci.tsv", sep="\t", header=None, names=["label", "text"])
    en["y"] = (en["label"] == "spam").astype(int)
    en["subset"] = "en_uci"

    ru = pd.read_csv(ROOT / "data" / "ru_kz_synthetic.csv")
    ru["y"] = (ru["label"] == "scam").astype(int)
    ru["subset"] = "ru_kz_synthetic"
    return en, ru


def split(en: pd.DataFrame, ru: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    en_train, en_test = train_test_split(en, test_size=0.2, stratify=en["y"], random_state=SEED)
    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    train_idx, test_idx = next(sgkf.split(ru, ru["y"], groups=ru["template_id"]))
    train = pd.concat([en_train, ru.iloc[train_idx]], ignore_index=True)
    test = pd.concat([en_test, ru.iloc[test_idx]], ignore_index=True)
    return train, test


def metrics(y_true, y_pred) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "n": int(len(y_true)),
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "false_positives": int(fp),
        "false_negatives": int(fn),
    }


def evaluate(detector: ScamDetector, test: pd.DataFrame) -> dict:
    texts = test["text"].tolist()
    ml = detector.ml_probability(texts)
    rules = [rules_score(find_red_flags(t)) for t in texts]
    test = test.assign(
        ml_pred=[int(p >= THRESHOLD) for p in ml],
        rules_pred=[int(r >= THRESHOLD) for r in rules],
        hybrid_pred=[int(ML_WEIGHT * p + RULES_WEIGHT * r >= THRESHOLD) for p, r in zip(ml, rules)],
    )
    report = {}
    for subset, part in [("all", test), *test.groupby("subset")]:
        report[subset] = {
            name: metrics(part["y"], part[f"{name}_pred"]) for name in ("ml", "rules", "hybrid")
        }
    return report


def print_report(report: dict) -> None:
    for subset, by_model in report.items():
        print(f"\n== {subset} (n={by_model['hybrid']['n']}) ==")
        print(f"{'model':<8}{'acc':>8}{'prec':>8}{'recall':>8}{'f1':>8}{'FP':>6}{'FN':>6}")
        for name, m in by_model.items():
            print(
                f"{name:<8}{m['accuracy']:>8.3f}{m['precision']:>8.3f}{m['recall']:>8.3f}"
                f"{m['f1']:>8.3f}{m['false_positives']:>6}{m['false_negatives']:>6}"
            )


def main() -> None:
    en, ru = load_data()
    train, test = split(en, ru)
    print(f"Train: {len(train)} messages, test: {len(test)} messages")

    detector = ScamDetector(build_pipeline().fit(train["text"], train["y"]))
    report = evaluate(detector, test)
    print_report(report)
    (ROOT / "models").mkdir(exist_ok=True)
    (ROOT / "models" / "metrics.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))

    full = pd.concat([en, ru], ignore_index=True)
    final = ScamDetector(build_pipeline().fit(full["text"], full["y"]))
    final.save()
    print(f"\nFinal model trained on all {len(full)} messages and saved to models/scam_detector.joblib")


if __name__ == "__main__":
    main()
