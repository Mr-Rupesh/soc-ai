# api/main.py
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  # Must import first — activates LangSmith tracing before anything else

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone
from typing import Any
import asyncio

from alerts.schemas import AlertSchema
from alerts.db import init_db, save_alert, update_alert_result, get_alert, get_all_alerts, clear_all
from api.models import IngestResponse, StatusResponse, AlertSummary
from pipeline.graph import compiled_graph

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SOC-AI API",
    description="Async bridge between alert sources, LangGraph pipeline, and Streamlit UI",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Initialize SQLite on startup ────────────────────────────────────────────
init_db()


# ── Helper ─────────────────────────────────────────────────────────────────────
async def run_pipeline(alert_id: str, alert: AlertSchema):
    """
    Runs the alert through the real LangGraph pipeline. Same async-bridging
    logic as before — asyncio.to_thread() keeps FastAPI's event loop free
    while the blocking Groq/OTX/ChromaDB calls run in a separate thread.
    """
    initial_state = {"alert": alert.model_dump(mode="json"), "errors": []}

    try:
        final_state = await asyncio.to_thread(compiled_graph.invoke, initial_state)

        result = {
            "final_report":     final_state.get("final_report"),
            "triage_severity":  final_state.get("triage_severity"),
            "attack_type":      final_state.get("attack_type"),
            "mitre_id":         final_state.get("mitre_id"),
            "hitl_required":    final_state.get("hitl_required"),
            "hitl_approved":    None,  # unset until analyst acts
            "ir_actions":       final_state.get("ir_actions"),
            "errors":           final_state.get("errors", []),
        }
        update_alert_result(alert_id, result)

        print(f"  ✅ [Pipeline] Alert {alert_id[:8]}... completed | "
              f"Severity: {final_state.get('triage_severity')} | "
              f"HITL: {final_state.get('hitl_required')}")

    except Exception as e:
        update_alert_result(alert_id, {"status": "pipeline_error", "error": str(e)})
        print(f"  ❌ [Pipeline] Alert {alert_id[:8]}... failed: {e}")


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", response_model=StatusResponse)
async def health_check():
    all_alerts = get_all_alerts(limit=10000)  # count only — fine at this scale
    return StatusResponse(
        status="ok",
        total_alerts=len(all_alerts),
        pipeline_ready=True,
    )


@app.post("/alerts/ingest", response_model=IngestResponse)
async def ingest_alert(alert: AlertSchema, background_tasks: BackgroundTasks):
    save_alert(alert.alert_id, alert.model_dump(mode="json"))

    background_tasks.add_task(run_pipeline, alert.alert_id, alert)

    print(f"  📥 Received [{alert.severity}] {alert.event_type} — ID: {alert.alert_id[:8]}...")

    return IngestResponse(
        success   = True,
        alert_id  = alert.alert_id,
        message   = "Alert queued for processing",
        timestamp = datetime.now(timezone.utc),
    )


@app.get("/alerts", response_model=list[AlertSummary])
async def get_alerts(limit: int = 50):
    records = get_all_alerts(limit=limit)
    summaries = []
    for record in records:
        a = record["alert"]
        summaries.append(AlertSummary(
            alert_id   = a["alert_id"],
            event_type = a["event_type"],
            severity   = a["severity"],
            hostname   = a["hostname"],
            source_ip  = a["source_ip"],
            timestamp  = a["timestamp"],
            processed  = record["processed"],
            result     = record["result"],
        ))
    return summaries


@app.get("/alerts/{alert_id}")
async def get_alert_by_id(alert_id: str):
    record = get_alert(alert_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return record


@app.delete("/alerts/clear")
async def clear_alerts():
    count = clear_all()
    return {"cleared": count}


from pipeline.hitl import approve_alert, reject_alert
from pydantic import BaseModel

class HitlDecision(BaseModel):
    analyst_note: str = ""


@app.post("/alerts/{alert_id}/approve")
async def approve(alert_id: str, decision: HitlDecision):
    record = get_alert(alert_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    try:
        updated = approve_alert(record, decision.analyst_note)
        update_alert_result(alert_id, updated["result"])
        return {"success": True, "alert_id": alert_id, "hitl_approved": True}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/alerts/{alert_id}/reject")
async def reject(alert_id: str, decision: HitlDecision):
    record = get_alert(alert_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    try:
        updated = reject_alert(record, decision.analyst_note)
        update_alert_result(alert_id, updated["result"])
        return {"success": True, "alert_id": alert_id, "hitl_approved": False}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))