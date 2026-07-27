# alerts/db.py
"""
SQLite persistence for alert_store.

Job: Replace api/main.py's in-memory dict with a file-backed store so alerts
survive server restarts. Same shape as before (alert_id -> record dict),
just backed by disk instead of RAM.
"""
import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import Any, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "alerts.db")


def _get_conn():
    # check_same_thread=False: FastAPI's asyncio.to_thread() runs pipeline
    # code in a different thread than the request handler — SQLite's default
    # blocks cross-thread access, so this is required, not optional.
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row  # lets us access columns by name, like a dict
    return conn


def init_db():
    """Call once at FastAPI startup. Creates the table if it doesn't exist."""
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id   TEXT PRIMARY KEY,
            alert_json TEXT NOT NULL,      -- the full AlertSchema dict, as JSON
            processed  INTEGER NOT NULL DEFAULT 0,
            result_json TEXT,               -- pipeline result dict, as JSON (NULL until processed)
            received   TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
    print(f"  💾 SQLite ready at {DB_PATH}")


def save_alert(alert_id: str, alert_dict: dict):
    """Called when a new alert is ingested — before pipeline runs."""
    conn = _get_conn()
    conn.execute(
        "INSERT INTO alerts (alert_id, alert_json, processed, result_json, received) VALUES (?, ?, 0, NULL, ?)",
        (alert_id, json.dumps(alert_dict), datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    conn.close()


def update_alert_result(alert_id: str, result_dict: dict):
    """Called when the pipeline finishes processing an alert."""
    conn = _get_conn()
    conn.execute(
        "UPDATE alerts SET processed = 1, result_json = ? WHERE alert_id = ?",
        (json.dumps(result_dict), alert_id),
    )
    conn.commit()
    conn.close()


def get_alert(alert_id: str) -> Optional[dict]:
    """Fetch one alert record, same shape as the old in-memory dict."""
    conn = _get_conn()
    row = conn.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,)).fetchone()
    conn.close()
    if not row:
        return None
    return _row_to_record(row)


def get_all_alerts(limit: int = 50) -> list[dict]:
    """Most recent alerts first — same shape as the old GET /alerts loop."""
    conn = _get_conn()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY received DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [_row_to_record(row) for row in rows]


def clear_all():
    conn = _get_conn()
    count = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    conn.execute("DELETE FROM alerts")
    conn.commit()
    conn.close()
    return count


def _row_to_record(row: sqlite3.Row) -> dict:
    """Reconstructs the same {alert, processed, result, received} shape
    api/main.py already expects — minimizes changes needed elsewhere."""
    return {
        "alert":     json.loads(row["alert_json"]),
        "processed": bool(row["processed"]),
        "result":    json.loads(row["result_json"]) if row["result_json"] else None,
        "received":  row["received"],
    }