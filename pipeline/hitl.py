# pipeline/hitl.py
"""
HITL (Human-In-The-Loop) Logic — analyst approval/rejection for CRITICAL alerts.

Job   : Not a LangGraph node. This is called directly by a FastAPI endpoint
        when an analyst clicks Approve/Reject on the Streamlit dashboard.
Why not a graph node: the pipeline has already finished by the time a human
        reviews it (alert is sitting in alert_store with hitl_required=True).
        Re-running the graph would waste Groq/OTX calls for no reason —
        approval is a stateful decision on already-computed output, not a
        new pipeline step.
"""
from datetime import datetime, timezone


def approve_alert(alert_record: dict, analyst_note: str = "") -> dict:
    """
    Marks an alert's IR plan as approved for execution.

    alert_record is the dict stored in api/main.py's alert_store[alert_id] —
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