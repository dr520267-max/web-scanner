"""
app.py - Streamlit frontend for the Automated Web Scanner.

Run:  streamlit run app.py
"""
import json
import os

import pandas as pd
import requests
import streamlit as st

API_URL = os.environ.get("SCANNER_API_URL", "http://127.0.0.1:5000")
API_KEY = os.environ.get("SCANNER_API_KEY", "")

SEV_ICON = {"critical": "🟣", "high": "🔴", "medium": "🟠", "low": "🟡", "info": "🟢"}

st.set_page_config(page_title="Web Security Scanner", page_icon="🛡️", layout="wide")
st.title("🛡️ Automated Web Security Scanner")
st.caption("Audits security headers, cookie flags and CORS configuration.")

with st.form("scan_form"):
    url = st.text_input("Target URL", placeholder="https://example.com")
    authorized = st.checkbox("I own this site or have written permission to test it.")
    submitted = st.form_submit_button("Run scan", type="primary")

if submitted:
    if not url.strip():
        st.warning("Enter a URL.")
    elif not authorized:
        st.error("Please confirm you are authorized to scan this target.")
    else:
        with st.spinner("Scanning..."):
            try:
                r = requests.post(
                    f"{API_URL}/api/scan",
                    json={"url": url, "authorized": True},
                    headers={"X-API-Key": API_KEY} if API_KEY else {},
                    timeout=90,
                )
                data = r.json()
                if r.status_code != 200:
                    st.error(data.get("error", "Scan failed."))
                    st.stop()
                st.session_state["result"] = data
            except requests.RequestException:
                st.error(f"Cannot reach backend at {API_URL}. Is api.py running?")
                st.stop()

res = st.session_state.get("result")
if res:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Grade", res["grade"])
    c2.metric("Score", f'{res["score"]}/100')
    c3.metric("HTTP status", res["status_code"])
    c4.metric("Issues", sum(res["summary"].values()))
    st.write(f'**Scanned:** `{res["final_url"]}`')

    s = res["summary"]
    st.write(f'{SEV_ICON["critical"]} Critical: {s["critical"]}  |  '
             f'{SEV_ICON["high"]} High: {s["high"]}  |  '
             f'{SEV_ICON["medium"]} Medium: {s["medium"]}  |  '
             f'{SEV_ICON["low"]} Low: {s["low"]}')

    findings = res["findings"]
    tabs = st.tabs(["All", "Headers", "Cookies", "CORS"])
    for tab, cat in zip(tabs, [None, "headers", "cookies", "cors"]):
        with tab:
            items = [f for f in findings if cat is None or f["category"] == cat]
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            items.sort(key=lambda f: (f["status"] == "pass", order[f["severity"]]))
            for f in items:
                icon = SEV_ICON[f["severity"]] if f["status"] == "fail" else "✅"
                with st.expander(f'{icon} {f["title"]}  ·  {f["severity"].upper() if f["status"]=="fail" else "PASS"}'):
                    st.write(f["detail"])
                    if f["recommendation"] and f["status"] == "fail":
                        st.info(f'**Fix:** {f["recommendation"]}')

    d1, d2 = st.columns(2)
    d1.download_button("Download JSON report", json.dumps(res, indent=2),
                       "scan_report.json", "application/json")
    d2.download_button("Download CSV", pd.DataFrame(findings).to_csv(index=False),
                       "scan_report.csv", "text/csv")
