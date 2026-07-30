import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import config  

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from datetime import datetime, timezone
from typing import Optional, Any
import asyncio

from alerts.schemas import AlertSchema
from alerts.db import init_db, save_alert, update_alert_result, get_alert, get_all_alerts, clear_all
from pipeline.graph import compiled_graph


# ── Response models (merged from api/models.py) ───────────────────────────────

class IngestResponse(BaseModel):
    """Returned to the caller after an alert is received."""
    success:   bool
    alert_id:  str
    message:   str
    timestamp: datetime


class StatusResponse(BaseModel):
    """Health check response."""
    status:      str
    total_alerts: int
    pipeline_ready: bool


class AlertSummary(BaseModel):
    """Lightweight alert info for dashboard listing — not the full schema."""
    alert_id:   str
    event_type: str
    severity:   str
    hostname:   str
    source_ip:  str
    timestamp:  datetime
    processed:  bool
    result:     Optional[Any] = None


class HitlDecision(BaseModel):
    analyst_note: str = ""


# ── HITL logic (merged from pipeline/hitl.py) ──────────────────────────────────

def approve_alert(alert_record: dict, analyst_note: str = "") -> dict:
    """
    Marks an alert's IR plan as approved for execution.

    alert_record is the dict stored in alert_store[alert_id] —
    mutated in place and returned for clarity, not a new object.
    """
    if not alert_record.get("result"):
        raise ValueError("Cannot approve an alert that hasn't finished processing")

    alert_record["result"]["hitl_approved"] = True
    alert_record["result"]["hitl_decision_at"] = datetime.now(timezone.utc).isoformat()
    alert_record["result"]["hitl_analyst_note"] = analyst_note

    print(f"  ✅ [HITL] Alert approved — IR actions cleared for execution")
    return alert_record


def reject_alert(alert_record: dict, analyst_note: str = "") -> dict:
    """
    Marks an alert's IR plan as rejected — e.g. analyst determined it's a
    false positive. This is also the hook point for the feedback loop:
    a rejected alert should be written back to ChromaDB with
    false_positive=True so future similar alerts reference the correction.
    """
    if not alert_record.get("result"):
        raise ValueError("Cannot reject an alert that hasn't finished processing")

    alert_record["result"]["hitl_approved"] = False
    alert_record["result"]["hitl_decision_at"] = datetime.now(timezone.utc).isoformat()
    alert_record["result"]["hitl_analyst_note"] = analyst_note

    # ── Feedback loop hook ──────────────────────────────────────────────
    # Write back to ChromaDB marking this as a false positive, so future
    # find_similar() calls surface "this pattern was previously rejected."
    from memory.chromadb_manager import store_alert

    store_alert(
        alert=alert_record["alert"],
        pipeline_result={
            "attack_type":    alert_record["result"].get("attack_type", "unknown"),
            "mitre_id":       alert_record["result"].get("mitre_id", "unknown"),
            "false_positive": True,
        },
    )

    print(f"  ❌ [HITL] Alert rejected — false positive recorded in ChromaDB")
    return alert_record


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
            "final_report":       final_state.get("final_report"),
            "triage_severity":    final_state.get("triage_severity"),
            "triage_confidence":  final_state.get("triage_confidence"),
            "attack_type":        final_state.get("attack_type"),
            "mitre_id":           final_state.get("mitre_id"),
            "mitre_technique":    final_state.get("mitre_technique"),
            "analysis_confidence":final_state.get("analysis_confidence"),
            "analysis_reasoning": final_state.get("analysis_reasoning"),
            "otx_indicators":     final_state.get("otx_indicators"),
            "hitl_required":      final_state.get("hitl_required"),
            "hitl_approved":      None,  # unset until analyst acts
            "ir_actions":         final_state.get("ir_actions"),
            "errors":             final_state.get("errors", []),
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
    all_alerts = get_all_alerts(limit=10000)  
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