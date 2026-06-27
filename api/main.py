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

# ── App setup ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SOC-AI API",
    description="Async bridge between alert sources, LangGraph pipeline, and Streamlit UI",
    version="0.1.0",
)

# Allow Streamlit (running on port 8501) to call this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501", "http://127.0.0.1:8501"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── In-memory alert store ──────────────────────────────────────────────────────
# Week 1: simple dict. Week 2: this feeds ChromaDB + pipeline results.
# Key = alert_id, Value = dict with alert data + processing state
alert_store: dict[str, dict[str, Any]] = {}


# ── Helper ─────────────────────────────────────────────────────────────────────
async def run_pipeline(alert_id: str, alert: AlertSchema):
    """
    Placeholder for the LangGraph pipeline.
    Week 2: this calls pipeline/graph.py with the alert.
    For now: simulates processing with a 2-second delay.
    
    Runs as a BackgroundTask — FastAPI returns the ingest response immediately,
    then this runs after. This is why the dashboard shows 'processed: False'
    briefly after an alert arrives.
    """
    await asyncio.sleep(2)  # Placeholder — replace with actual pipeline call in Week 2
    alert_store[alert_id]["processed"] = True
    alert_store[alert_id]["result"]    = {"status": "pipeline_placeholder — Week 2"}
    print(f"  🔄 [Pipeline placeholder] Alert {alert_id[:8]}... marked processed")


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health", response_model=StatusResponse)
async def health_check():
    """
    Streamlit calls this first to confirm API is alive.
    Also shows how many alerts have been received.
    """
    return StatusResponse(
        status="ok",
        total_alerts=len(alert_store),
        pipeline_ready=False,   # Becomes True in Week 2
    )


@app.post("/alerts/ingest", response_model=IngestResponse)
async def ingest_alert(alert: AlertSchema, background_tasks: BackgroundTasks):
    """
    Main entry point — generator POSTs here.
    
    1. FastAPI automatically validates incoming JSON against AlertSchema
       If a field is wrong/missing → 422 error returned, no code needed
    2. Store alert in memory
    3. Queue pipeline run as background task (non-blocking)
    4. Return confirmation immediately so generator isn't waiting
    """
    # Store with processing state
    alert_store[alert.alert_id] = {
        "alert":     alert.model_dump(mode="json"),
        "processed": False,
        "result":    None,
        "received":  datetime.now(timezone.utc).isoformat(),
    }

    # Queue pipeline — runs after response is sent
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
    """
    Streamlit dashboard calls this to get the alert list.
    Returns most recent alerts first, up to `limit`.
    """
    summaries = []
    # Reverse order so newest alerts appear first
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
    """Get full detail for one alert — Streamlit uses this for the detail view."""
    if alert_id not in alert_store:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert_store[alert_id]


@app.delete("/alerts/clear")
async def clear_alerts():
    """Dev utility — clears all alerts from memory. Useful during testing."""
    count = len(alert_store)
    alert_store.clear()
    return {"cleared": count}