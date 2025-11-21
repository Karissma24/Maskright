import os, hmac, hashlib, json
from datetime import datetime, timezone
import requests, streamlit as st

# --- Config (prefer Streamlit secrets in prod, env in dev) ---
API_BASE_URL = os.getenv("API_BASE_URL", st.secrets.get("API_BASE_URL", ""))
HMAC_SECRET  = (os.getenv("HMAC_SECRET") or st.secrets.get("HMAC_SECRET") or "").encode()

def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def sign(ts: str, body: dict | None) -> str:
    payload = json.dumps(body, separators=(",", ":"), ensure_ascii=False) if body else ""
    return hmac.new(HMAC_SECRET, f"{ts}{payload}".encode(), hashlib.sha256).hexdigest()

def api_get(path: str, params: dict | None = None):
    ts = now_iso()
    headers = {
        "X-Timestamp": ts,
        "X-Signature": sign(ts, None),
        "Accept": "application/json",
    }
    url = f"{API_BASE_URL}{path}"
    r = requests.get(url, headers=headers, params=params, timeout=12)
    r.raise_for_status()
    return r.json()

st.set_page_config(page_title="Secure PII Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ Secure PII Dashboard (Masked Only)")

# Controls
col1, col2 = st.columns([1,1])
with col1:
    limit = st.number_input("Rows", min_value=10, max_value=500, value=100, step=10)
with col2:
    refresh = st.button("Refresh")

# Guardrails
if not API_BASE_URL or not HMAC_SECRET:
    st.error("API_BASE_URL or HMAC_SECRET not set. Add them in secrets or env.")
    st.stop()

# Fetch data
try:
    data = api_get("/query", params={"limit": limit})
except Exception as e:
    st.error(f"Query failed: {e}")
    st.stop()

count = int(data.get("count", 0))
items = data.get("items", [])

# KPIs
c1, c2 = st.columns(2)
c1.metric("Total masked records", f"{count:,}")
c2.metric("Shown", f"{len(items):,}")

# Table
if items:
    cols = ["id","name","email","phone","created_at"]
    rows = [{k: it.get(k,"") for k in cols} for it in items]
    st.dataframe(rows, use_container_width=True, hide_index=True)
else:
    st.info("No data yet. Submit via the web form to see masked records.")

st.caption("All calls use TLS + HMAC. Only masked data is returned. Logs are redacted (IDs + timestamps only).")
