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
from api.models import IngestResponse, StatusResponse, AlertSummary
from pipeline.graph import compiled_graph  # ← real pipeline, built once at import

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

# ── In-memory alert store ──────────────────────────────────────────────────────
alert_store: dict[str, dict[str, Any]] = {}


# ── Helper ─────────────────────────────────────────────────────────────────────
async def run_pipeline(alert_id: str, alert: AlertSchema):
    """
    Runs the alert through the real LangGraph pipeline (Triage → Analysis →
    Memory → Response → Report). Replaces the Week 1 placeholder.

    Why asyncio.to_thread(): compiled_graph.invoke() is SYNCHRONOUS — Groq/OTX/
    ChromaDB calls inside your agents are all blocking calls, not async. If we
    called invoke() directly inside this async function, it would BLOCK the
    entire FastAPI event loop while the pipeline runs (several seconds per
    alert), freezing every other request — including /health checks from
    Streamlit. to_thread() runs the blocking call in a separate thread so
    FastAPI stays responsive to other requests while this alert processes.
    This is the single most common async mistake with LangGraph + FastAPI.
    """
    initial_state = {"alert": alert.model_dump(mode="json"), "errors": []}

    try:
        final_state = await asyncio.to_thread(compiled_graph.invoke, initial_state)

        alert_store[alert_id]["processed"] = True
        alert_store[alert_id]["result"] = {
            "final_report":     final_state.get("final_report"),
            "triage_severity":  final_state.get("triage_severity"),
            "attack_type":      final_state.get("attack_type"),
            "mitre_id":         final_state.get("mitre_id"),
            "hitl_required":    final_state.get("hitl_required"),
            "ir_actions":       final_state.get("ir_actions"),
            "errors":           final_state.get("errors", []),
        }
        print(f"  ✅ [Pipeline] Alert {alert_id[:8]}... completed | "
              f"Severity: {final_state.get('triage_severity')} | "
              f"HITL: {final_state.get('hitl_required')}")

    except Exception as e:
        # Pipeline-level failure (shouldn't happen often — each agent has its
        # own try/except — but this catches anything that slips through, e.g.
        # a LangGraph routing error, so the dashboard shows a clear failure
        # state instead of hanging on "processed: False" forever.
        alert_store[alert_id]["processed"] = True
        alert_store[alert_id]["result"] = {"status": "pipeline_error", "error": str(e)}
        print(f"  ❌ [Pipeline] Alert {alert_id[:8]}... failed: {e}")


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", response_model=StatusResponse)
async def health_check():
    return StatusResponse(
        status="ok",
        total_alerts=len(alert_store),
        pipeline_ready=True,   # ← now True, real pipeline is wired in
    )


@app.post("/alerts/ingest", response_model=IngestResponse)
async def ingest_alert(alert: AlertSchema, background_tasks: BackgroundTasks):
    alert_store[alert.alert_id] = {
        "alert":     alert.model_dump(mode="json"),
        "processed": False,
        "result":    None,
        "received":  datetime.now(timezone.utc).isoformat(),
    }

    background_tasks.add_task(run_pipeline, alert.alert_id, alert)

    print(f"  📥 Received [{alert.severity}] {alert.event_type} — ID: {alert.alert_id[:8]}...")

    return IngestResponse(
        success   = True,
        alert_id  = alert.alert_id,
        message   = f"Alert queued for processing",
        timestamp = datetime.now(timezone.utc),
    )


@app.get("/alerts", response_model=list[AlertSummary])
async def get_alerts(limit: int = 50):
    summaries = []
    for alert_id, record in list(reversed(list(alert_store.items())))[:limit]:
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
async def get_alert(alert_id: str):
    if alert_id not in alert_store:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert_store[alert_id]


@app.delete("/alerts/clear")
async def clear_alerts():
    count = len(alert_store)
    alert_store.clear()
    return {"cleared": count}