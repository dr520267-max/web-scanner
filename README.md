# 🛡️ Automated Web Security Scanner

A Python tool that audits websites for **missing security headers**, **weak cookie flags** and **CORS misconfigurations**. It has a Flask REST API backend and a Streamlit web interface, and it grades each target from A to F with a fix recommendation for every issue found.

> ⚠️ **Legal notice:** Only scan websites you own or have **written permission** to test. Unauthorized scanning may be illegal.

---

## Features

- **Security header audit:** HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP/CORP, and technology-disclosure headers (`Server`, `X-Powered-By`).
- **Cookie audit:** checks `Secure`, `HttpOnly` and `SameSite` attributes.
- **Active CORS testing:** detects origin reflection, `null` origin trust, wildcard with credentials, weak suffix/prefix matching, missing `Vary: Origin` and permissive preflight responses.
- **Scoring:** 0–100 score, A–F grade and severity levels (Critical, High, Medium, Low).
- **Reports:** download results as JSON or CSV.
- **Built-in safeguards:** SSRF protection, redirect re-validation, rate limiting, optional API key and a mandatory authorization confirmation.

## Project Structure

```
websec_scanner/
├── scanner.py          # Core scanning engine
├── api.py              # Flask REST API (backend)
├── app.py              # Streamlit dashboard (frontend)
├── requirements.txt    # Python dependencies
└── README.md
```

## Requirements

- Python 3.10 or newer
- Internet access to the target site

## Installation

```powershell
# 1. Open a terminal in the project folder
cd "path\to\websec_scanner"

# 2. Create a virtual environment
python -m venv venv

# 3. Activate it
venv\Scripts\Activate.ps1          # Windows PowerShell
# source venv/bin/activate         # macOS / Linux

# 4. Install dependencies
pip install -r requirements.txt
```

> **Windows tip:** if activation is blocked, run
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` once, then activate again.
> Folder names with spaces must be quoted: `cd "Cyber security"`.

## Usage

Run the backend and frontend in **two separate terminals** (activate the virtual environment in both).

**Terminal 1: backend**
```bash
python api.py
```
The API runs at `http://127.0.0.1:5000`. Check it at `/health`.

**Terminal 2: frontend**
```bash
streamlit run app.py
```
The dashboard opens at `http://localhost:8501`.

Then:
1. Enter the target URL (e.g. `https://yourdomain.com`).
2. Tick the authorization checkbox.
3. Click **Run scan** and review the grade, findings and fixes.
4. Download the JSON or CSV report if needed.

## API Reference

### `GET /health`
Returns `{"status": "ok"}`.

### `POST /api/scan`

**Request body**
```json
{ "url": "https://example.com", "authorized": true }
```

**Example**
```bash
curl -X POST http://127.0.0.1:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com","authorized":true}'
```

**Response (shortened)**
```json
{
  "target": "https://example.com",
  "final_url": "https://example.com/",
  "status_code": 200,
  "score": 55,
  "grade": "D",
  "summary": { "critical": 0, "high": 1, "medium": 2, "low": 3 },
  "findings": [
    {
      "category": "headers",
      "title": "Content-Security-Policy",
      "severity": "high",
      "status": "fail",
      "detail": "Header missing; weaker XSS mitigation.",
      "recommendation": "Define a restrictive CSP, e.g. default-src 'self'."
    }
  ]
}
```

**Status codes**

| Code | Meaning |
|------|---------|
| 200 | Scan completed |
| 400 | Invalid URL, blocked target or missing authorization flag |
| 401 | Wrong or missing API key (when enabled) |
| 429 | Rate limit exceeded (10 scans/minute per IP) |
| 500 | Internal error |

## Configuration

| Variable | Used by | Description |
|----------|---------|-------------|
| `SCANNER_API_KEY` | backend + frontend | Optional shared secret sent as `X-API-Key` |
| `SCANNER_API_URL` | frontend | Backend address (default `http://127.0.0.1:5000`) |

Set them before starting each program:

```powershell
$env:SCANNER_API_KEY = "mysecret"      # Windows PowerShell
# export SCANNER_API_KEY=mysecret      # macOS / Linux
```

Other tunables: `RATE_LIMIT` and `WINDOW` in `api.py`; `TIMEOUT` and `MAX_REDIRECTS` in `scanner.py`.

## Scoring

The score starts at 100 and loses points for each failed check:

| Severity | Penalty | | Score | Grade |
|----------|---------|-|-------|-------|
| Critical | −30 | | 90–100 | A |
| High | −20 | | 80–89 | B |
| Medium | −10 | | 65–79 | C |
| Low | −5 | | 50–64 | D |
| | | | < 50 | F |

## Security Design

- Hostnames are resolved and **private, loopback and link-local addresses are blocked** (SSRF protection).
- Redirects are followed manually and **each hop is re-validated**.
- Only `GET` and `OPTIONS` requests are made; response bodies are not downloaded.
- Internal errors are logged server-side and never shown to the client.

> Scanning `localhost` or LAN addresses is blocked on purpose. To test a local development site, temporarily relax the `is_global` check in `validate_url()` in `scanner.py` and restore it afterward.

## Troubleshooting

| Problem | Fix |
|---------|-----|
| `Cannot reach backend` | Start `python api.py` first |
| `running scripts is disabled` | Run `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned` |
| `cd` fails on a folder with spaces | Wrap the path in quotes |
| `python venv\Scripts\activate` gives a SyntaxError | Do not prefix with `python`; run `venv\Scripts\Activate.ps1` |
| `Could not resolve hostname` | Check URL spelling and internet connection |
| HTTP 429 | Wait a minute or raise `RATE_LIMIT` |

## Limitations

- Scans a single URL; no crawling.
- Unauthenticated checks only.
- CSP analysis is heuristic.
- The in-memory rate limiter is per process and resets on restart.
- DNS-rebinding attacks are not fully mitigated; run public deployments in an isolated container.
- A good grade does not mean a site is fully secure. This tool checks HTTP-layer configuration only.

## Roadmap

- [ ] Multi-page crawling
- [ ] TLS/certificate analysis
- [ ] `security.txt` and SRI checks
- [ ] Scan history database
- [ ] Async bulk scanning
- [ ] PDF reports
- [ ] Docker image

## Production Deployment

```bash
gunicorn -w 2 -b 127.0.0.1:5000 api:app
```
Place it behind a reverse proxy (HTTPS), set `SCANNER_API_KEY`, and use a shared rate-limit store such as Redis when running multiple workers.

## License

Add your preferred license (e.g. MIT) here.

## Disclaimer

This tool is provided for educational and authorized security testing only. The author is not responsible for misuse.
