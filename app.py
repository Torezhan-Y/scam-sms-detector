"""Web demo: paste an SMS, get a verdict with reasons.

Run:  python app.py   then open http://127.0.0.1:5000
API:  POST /api/check  {"text": "..."}  ->  JSON verdict
"""

from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from src.detector.model import ScamDetector

MAX_LEN = 1000

app = Flask(__name__)
detector = ScamDetector.load()


def verdict_dict(text: str) -> dict:
    v = detector.check(text)
    return {
        "is_scam": v.is_scam,
        "label": v.label,
        "score": v.score,
        "ml_probability": v.ml_probability,
        "rules_score": v.rules_score,
        "reasons": [f.reason for f in v.flags],
    }


@app.route("/", methods=["GET", "POST"])
def index():
    text = (request.form.get("text") or "")[:MAX_LEN]
    result = verdict_dict(text) if text.strip() else None
    return render_template("index.html", text=text, result=result)


@app.post("/api/check")
def api_check():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text", ""))[:MAX_LEN]
    if not text.strip():
        return jsonify({"error": "Field 'text' is required"}), 400
    return jsonify(verdict_dict(text))


if __name__ == "__main__":
    app.run(debug=False)
