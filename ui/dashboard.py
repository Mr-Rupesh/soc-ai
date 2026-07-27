# ui/dashboard.py
"""
SOC-AI Streamlit Dashboard.

Job   : Analyst-facing UI. Polls FastAPI for alert data and displays it.
Rule  : NEVER imports LangGraph, agents, or pipeline code directly — Streamlit
        only talks to FastAPI via requests.get()/post(). This avoids the
        async conflict between Streamlit's execution model and LangGraph's
        blocking calls (same reasoning as api/main.py's asyncio.to_thread()).
"""
import streamlit as st
import requests
from datetime import datetime

API_BASE = "http://127.0.0.1:8000"

st.set_page_config(page_title="SOC-AI Dashboard", layout="wide")
st.title("🛡️ SOC-AI — Security Operations Dashboard")


# ── Health check ─────────────────────────────────────────────────────────────
def check_health():
    try:
        r = requests.get(f"{API_BASE}/health", timeout=3)
        return r.json() if r.status_code == 200 else None
    except requests.exceptions.ConnectionError:
        return None


health = check_health()
if not health:
    st.error("⚠️ FastAPI is not reachable at " + API_BASE + " — start it with `uvicorn api.main:app --reload`")
    st.stop()

col1, col2 = st.columns(2)
col1.metric("Pipeline Status", "✅ Ready" if health["pipeline_ready"] else "❌ Not Ready")
col2.metric("Total Alerts", health["total_alerts"])

st.divider()


# ── Fetch alerts ─────────────────────────────────────────────────────────────
def fetch_alerts():
    try:
        r = requests.get(f"{API_BASE}/alerts?limit=50", timeout=5)
        return r.json() if r.status_code == 200 else []
    except requests.exceptions.ConnectionError:
        return []


alerts = fetch_alerts()

if not alerts:
    st.info("No alerts yet. Run the generator: `python -c \"from alerts.generator import run_generator; run_generator()\"`")
    st.stop()


# ── Manual refresh — simpler than auto-refresh, avoids surprise reruns ──────
if st.button("🔄 Refresh"):
    st.rerun()

st.caption(f"Showing {len(alerts)} most recent alerts")


# ── Render each alert as an expandable card ─────────────────────────────────
for alert in alerts:
    result = alert.get("result") or {}
    hitl_required = result.get("hitl_required", False)
    hitl_approved = result.get("hitl_approved")  # None = undecided

    # Visual flag for anything needing analyst attention
    needs_review = hitl_required and hitl_approved is None
    icon = "🔴" if needs_review else ("🟡" if hitl_required else "🟢")

    with st.expander(
        f"{icon} [{alert['severity']}] {alert['event_type']} — {alert['hostname']} "
        f"({alert['source_ip']}) — {alert['alert_id'][:8]}...",
        expanded=needs_review,
    ):
        col_a, col_b = st.columns([2, 1])

        with col_a:
            if result.get("final_report"):
                st.markdown(result["final_report"])
            else:
                st.warning("Still processing — refresh in a moment." if not alert["processed"] else "No report available.")

        with col_b:
            st.write("**Attack Type:**", result.get("attack_type", "N/A"))
            st.write("**MITRE ID:**", result.get("mitre_id", "N/A"))
            st.write("**HITL Required:**", "Yes" if hitl_required else "No")

            if hitl_required:
                if hitl_approved is None:
                    st.warning("⏳ Awaiting analyst decision")
                    note = st.text_input("Analyst note", key=f"note_{alert['alert_id']}")

                    b1, b2 = st.columns(2)
                    if b1.button("✅ Approve", key=f"approve_{alert['alert_id']}"):
                        r = requests.post(
                            f"{API_BASE}/alerts/{alert['alert_id']}/approve",
                            json={"analyst_note": note},
                        )
                        if r.status_code == 200:
                            st.success("Approved")
                            st.rerun()
                        else:
                            st.error(f"Failed: {r.text}")

                    if b2.button("❌ Reject", key=f"reject_{alert['alert_id']}"):
                        r = requests.post(
                            f"{API_BASE}/alerts/{alert['alert_id']}/reject",
                            json={"analyst_note": note},
                        )
                        if r.status_code == 200:
                            st.success("Rejected — logged as false positive")
                            st.rerun()
                        else:
                            st.error(f"Failed: {r.text}")

                elif hitl_approved:
                    st.success("✅ Approved by analyst")
                else:
                    st.error("❌ Rejected — false positive")