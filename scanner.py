"""
scanner.py - Core engine for the Automated Web Scanner.

Passively audits a site's HTTP security headers, cookie flags and CORS policy.
Use ONLY on sites you own or have written permission to test.
"""
import ipaddress
import re
import socket
from dataclasses import dataclass, asdict
from urllib.parse import urljoin, urlparse

import requests

TIMEOUT = 8
MAX_REDIRECTS = 5
USER_AGENT = "WebSecAuditor/1.0 (authorized security audit)"

SEVERITY_WEIGHT = {"critical": 30, "high": 20, "medium": 10, "low": 5, "info": 0}


class ScanError(Exception):
    """Raised for invalid targets or network failures."""


@dataclass
class Finding:
    category: str        # headers | cookies | cors
    title: str
    severity: str        # critical | high | medium | low | info
    status: str          # pass | fail
    detail: str
    recommendation: str = ""


# --------------------------------------------------------------------------
# Target validation (prevents the scanner itself being abused for SSRF)
# --------------------------------------------------------------------------
def validate_url(url: str) -> str:
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ScanError("Only valid http/https URLs are allowed.")
    try:
        infos = socket.getaddrinfo(parsed.hostname, parsed.port or 443)
    except socket.gaierror:
        raise ScanError("Could not resolve hostname.")
    for info in infos:
        if not ipaddress.ip_address(info[4][0]).is_global:
            raise ScanError("Scanning private/internal addresses is blocked.")
    return url


@dataclass
class Response:
    url: str
    status: int
    headers: requests.structures.CaseInsensitiveDict
    set_cookies: list


def safe_request(method: str, url: str, headers: dict | None = None) -> Response:
    """HTTP request that re-validates every redirect hop."""
    hdrs = {"User-Agent": USER_AGENT, **(headers or {})}
    for _ in range(MAX_REDIRECTS + 1):
        url = validate_url(url)
        try:
            r = requests.request(method, url, headers=hdrs, timeout=TIMEOUT,
                                 allow_redirects=False, stream=True)
        except requests.RequestException as exc:
            raise ScanError(f"Request failed: {exc.__class__.__name__}")
        cookies = r.raw.headers.getlist("Set-Cookie") if r.raw else []
        resp = Response(url, r.status_code, r.headers, cookies)
        r.close()
        if 300 <= r.status_code < 400 and "Location" in r.headers:
            url = urljoin(url, r.headers["Location"])
            continue
        return resp
    raise ScanError("Too many redirects.")


# --------------------------------------------------------------------------
# Security header checks
# --------------------------------------------------------------------------
def check_headers(resp: Response) -> list[Finding]:
    h, out = resp.headers, []
    https = resp.url.startswith("https://")

    # HSTS
    hsts = h.get("Strict-Transport-Security")
    if not https:
        out.append(Finding("headers", "HTTPS not used", "high", "fail",
                           "Final URL is served over plain HTTP.",
                           "Serve the site over HTTPS and redirect HTTP to HTTPS."))
    elif not hsts:
        out.append(Finding("headers", "Strict-Transport-Security", "high", "fail",
                           "Header missing.",
                           "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    else:
        m = re.search(r"max-age=(\d+)", hsts, re.I)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            out.append(Finding("headers", "Strict-Transport-Security", "medium", "fail",
                               f"max-age={age} is too short.",
                               "Use max-age of at least 15552000 (180 days)."))
        else:
            out.append(Finding("headers", "Strict-Transport-Security", "info", "pass", hsts))

    # CSP
    csp = h.get("Content-Security-Policy")
    if not csp:
        out.append(Finding("headers", "Content-Security-Policy", "high", "fail",
                           "Header missing; weaker XSS mitigation.",
                           "Define a restrictive CSP, e.g. default-src 'self'."))
    else:
        weak = [t for t in ("'unsafe-inline'", "'unsafe-eval'") if t in csp]
        if re.search(r"(default|script)-src[^;]*\s\*(\s|;|$)", csp):
            weak.append("wildcard source")
        if weak:
            out.append(Finding("headers", "Content-Security-Policy", "medium", "fail",
                               f"Weak directives: {', '.join(weak)}.",
                               "Remove unsafe-* keywords; use nonces or hashes."))
        else:
            out.append(Finding("headers", "Content-Security-Policy", "info", "pass", "Present."))

    # Clickjacking
    xfo = h.get("X-Frame-Options")
    if not xfo and not (csp and "frame-ancestors" in csp):
        out.append(Finding("headers", "Clickjacking protection", "medium", "fail",
                           "Neither X-Frame-Options nor CSP frame-ancestors set.",
                           "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    else:
        out.append(Finding("headers", "Clickjacking protection", "info", "pass",
                           xfo or "CSP frame-ancestors present."))

    # MIME sniffing
    if (h.get("X-Content-Type-Options") or "").lower() != "nosniff":
        out.append(Finding("headers", "X-Content-Type-Options", "medium", "fail",
                           "Missing or not 'nosniff'.",
                           "Add X-Content-Type-Options: nosniff"))
    else:
        out.append(Finding("headers", "X-Content-Type-Options", "info", "pass", "nosniff"))

    # Referrer-Policy
    rp = (h.get("Referrer-Policy") or "").lower()
    if not rp:
        out.append(Finding("headers", "Referrer-Policy", "low", "fail", "Header missing.",
                           "Add Referrer-Policy: strict-origin-when-cross-origin"))
    elif rp in ("unsafe-url", "no-referrer-when-downgrade"):
        out.append(Finding("headers", "Referrer-Policy", "low", "fail",
                           f"Leaky value: {rp}", "Use strict-origin-when-cross-origin or stricter."))
    else:
        out.append(Finding("headers", "Referrer-Policy", "info", "pass", rp))

    # Permissions-Policy
    if not h.get("Permissions-Policy"):
        out.append(Finding("headers", "Permissions-Policy", "low", "fail", "Header missing.",
                           "Add Permissions-Policy: camera=(), microphone=(), geolocation=()"))
    else:
        out.append(Finding("headers", "Permissions-Policy", "info", "pass", "Present."))

    # Cross-origin isolation (informational)
    for name in ("Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy"):
        if not h.get(name):
            out.append(Finding("headers", name, "low", "fail", "Header missing.",
                               f"Consider adding {name} (e.g. same-origin)."))
        else:
            out.append(Finding("headers", name, "info", "pass", h[name]))

    # Information disclosure
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        val = h.get(name)
        if val and (name != "Server" or re.search(r"\d", val)):
            out.append(Finding("headers", f"{name} disclosure", "low", "fail",
                               f"Reveals technology: {val}",
                               f"Remove or genericize the {name} header."))
    return out


# --------------------------------------------------------------------------
# Cookie checks
# --------------------------------------------------------------------------
def check_cookies(resp: Response) -> list[Finding]:
    out = []
    for raw in resp.set_cookies:
        name = raw.split("=", 1)[0].strip()
        low = raw.lower()
        issues = []
        if resp.url.startswith("https://") and "secure" not in low:
            issues.append("Secure")
        if "httponly" not in low:
            issues.append("HttpOnly")
        if "samesite" not in low:
            issues.append("SameSite")
        if issues:
            out.append(Finding("cookies", f"Cookie '{name}'", "medium", "fail",
                               f"Missing attributes: {', '.join(issues)}.",
                               "Set Secure; HttpOnly; SameSite=Lax (or Strict)."))
        else:
            out.append(Finding("cookies", f"Cookie '{name}'", "info", "pass",
                               "Secure, HttpOnly and SameSite set."))
    return out


# --------------------------------------------------------------------------
# CORS checks
# --------------------------------------------------------------------------
def check_cors(url: str) -> list[Finding]:
    host = urlparse(url).hostname
    test_origins = {
        "arbitrary origin": "https://evil.example",
        "null origin": "null",
        "suffix-match bypass": f"https://{host}.evil.example",
        "prefix-match bypass": f"https://evil{host}",
    }
    out, any_issue = [], False

    for label, origin in test_origins.items():
        try:
            r = safe_request("GET", url, {"Origin": origin})
        except ScanError:
            continue
        acao = r.headers.get("Access-Control-Allow-Origin")
        acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        vary = r.headers.get("Vary", "")
        if not acao:
            continue

        if acao == origin and acac:
            sev, msg = "critical", "Reflects origin AND allows credentials: any site can read authenticated responses."
        elif acao == "null" and acac:
            sev, msg = "high", "Trusts 'null' origin with credentials (exploitable via sandboxed iframes)."
        elif acao == origin:
            sev, msg = "medium", "Reflects arbitrary Origin without credentials."
        elif acao == "null":
            sev, msg = "low", "Trusts 'null' origin."
        elif acao == "*" and acac:
            sev, msg = "medium", "Wildcard with credentials=true (invalid; indicates misconfiguration)."
        else:
            continue  # '*' alone or a fixed allow-listed origin is acceptable

        any_issue = True
        out.append(Finding("cors", f"CORS: {label}", sev, "fail",
                           f"Origin sent: {origin} -> ACAO: {acao}, credentials: {acac}. {msg}",
                           "Validate Origin against a strict server-side allow-list; never reflect it blindly."))
        if acao == origin and "origin" not in vary.lower():
            out.append(Finding("cors", "CORS: missing Vary: Origin", "low", "fail",
                               "Dynamic ACAO without 'Vary: Origin' can cause cache poisoning.",
                               "Add Vary: Origin."))

    # Preflight
    try:
        pf = safe_request("OPTIONS", url, {
            "Origin": "https://evil.example",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "authorization",
        })
        methods = pf.headers.get("Access-Control-Allow-Methods", "")
        allow_h = pf.headers.get("Access-Control-Allow-Headers", "")
        pf_origin = pf.headers.get("Access-Control-Allow-Origin")
        if pf_origin in ("https://evil.example", "*") and (
                "*" in methods or "*" in allow_h or re.search(r"PUT|DELETE|PATCH", methods, re.I)):
            any_issue = True
            out.append(Finding("cors", "CORS: permissive preflight", "medium", "fail",
                               f"Untrusted origin allowed. Methods: {methods or '-'}; Headers: {allow_h or '-'}",
                               "Restrict allowed methods/headers to what the API needs."))
    except ScanError:
        pass

    if not any_issue:
        out.append(Finding("cors", "CORS policy", "info", "pass",
                           "No dangerous CORS behaviour detected for the tested origins."))
    return out


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------
def grade(findings: list[Finding]) -> tuple[int, str]:
    score = 100 - sum(SEVERITY_WEIGHT[f.severity] for f in findings if f.status == "fail")
    score = max(score, 0)
    letter = ("A" if score >= 90 else "B" if score >= 80 else "C" if score >= 65
              else "D" if score >= 50 else "F")
    return score, letter


def scan(url: str) -> dict:
    url = validate_url(url)
    resp = safe_request("GET", url)
    findings = check_headers(resp) + check_cookies(resp) + check_cors(resp.url)
    score, letter = grade(findings)
    return {
        "target": url,
        "final_url": resp.url,
        "status_code": resp.status,
        "score": score,
        "grade": letter,
        "summary": {s: sum(1 for f in findings if f.status == "fail" and f.severity == s)
                    for s in ("critical", "high", "medium", "low")},
        "findings": [asdict(f) for f in findings],
    }
