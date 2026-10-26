"""
api.py - Flask backend exposing the scanner as a REST API.

Run:  python api.py          (dev)
      gunicorn -w 2 api:app  (production)
"""
import os
import time
from collections import defaultdict, deque

from flask import Flask, jsonify, request

from scanner import ScanError, scan

app = Flask(__name__)

API_KEY = os.environ.get("SCANNER_API_KEY")        # optional shared secret
RATE_LIMIT, WINDOW = 10, 60                         # 10 scans / minute / IP
_hits: dict[str, deque] = defaultdict(deque)


def rate_limited(ip: str) -> bool:
    now, q = time.time(), _hits[ip]
    while q and now - q[0] > WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/api/scan")
def api_scan():
    if API_KEY and request.headers.get("X-API-Key") != API_KEY:
        return jsonify(error="Unauthorized"), 401
    if rate_limited(request.remote_addr or "unknown"):
        return jsonify(error="Rate limit exceeded. Try again shortly."), 429

    data = request.get_json(silent=True) or {}
    url = data.get("url", "")
    if not isinstance(url, str) or not url.strip():
        return jsonify(error="Field 'url' is required."), 400
    if not data.get("authorized"):
        return jsonify(error="You must confirm you are authorized to scan this target."), 400

    try:
        return jsonify(scan(url))
    except ScanError as exc:
        return jsonify(error=str(exc)), 400
    except Exception:
        app.logger.exception("Unexpected scan failure")
        return jsonify(error="Internal error during scan."), 500


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
