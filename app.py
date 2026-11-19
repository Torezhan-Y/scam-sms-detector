"""Web demo: paste an SMS, get a verdict with reasons.

Run:  python app.py   then open http://127.0.0.1:8000
      (port 5000 is taken by AirPlay Receiver on macOS, so 8000 is the default;
       set PORT=... to change it)
API:  POST /api/check  {"text": "..."}  ->  JSON verdict
"""

from __future__ import annotations

import os

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
    port = int(os.environ.get("PORT", 8000))
    print(f"Open http://127.0.0.1:{port} in your browser")
    app.run(host="127.0.0.1", port=port, debug=False)
