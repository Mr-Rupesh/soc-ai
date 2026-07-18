# pipeline/graph.py
"""
Pipeline Graph — connects all 5 agents into a single LangGraph StateGraph.

Flow:
  Triage → (conditional) → Analysis → Memory → Response → Report
                    ↓ (skip if not escalated)
                  Memory → Response → Report

Why Memory/Response/Report always run, even for LOW severity:
  Every alert should get SOME report and SOME response plan (even if it's
  "no action needed") — only Analysis is gated, since it's the expensive
  Groq 70B call we want to conserve quota on (per your Week 1 decision).
"""
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config  # Must be first — activates LangSmith tracing
from langgraph.graph import StateGraph, END

from pipeline.state import PipelineState
from agents.triage import run_triage
from agents.analysis import run_analysis
from agents.memory import run_memory_agent
from agents.response import run_response
from agents.report import run_report


def route_after_triage(state: PipelineState) -> str:
    """
    Conditional edge function — LangGraph calls this after the triage node
    to decide which node runs next. Must return a string matching one of
    the keys in the conditional_edges mapping below.
    """
    if state.get("triage_escalate"):
        return "analysis"
    return "memory"  # skip Analysis, go straight to Memory


def build_graph():
    """
    Constructs and compiles the LangGraph StateGraph.
    Call this once (e.g. in api/main.py at startup) and reuse the compiled
    graph object — don't rebuild it on every alert.
    """
    graph = StateGraph(PipelineState)

    # ── Register nodes — each is one of your tested agent functions ────────
    graph.add_node("triage", run_triage)
    graph.add_node("analysis", run_analysis)
    graph.add_node("memory", run_memory_agent)
    graph.add_node("response", run_response)
    graph.add_node("report", run_report)

    # ── Entry point ──────────────────────────────────────────────────────
    graph.set_entry_point("triage")

    # ── Conditional branch after Triage ─────────────────────────────────
    graph.add_conditional_edges(
        "triage",
        route_after_triage,
        {
            "analysis": "analysis",
            "memory":   "memory",
        },
    )

    # ── Both branches converge here ──────────────────────────────────────
    graph.add_edge("analysis", "memory")
    graph.add_edge("memory", "response")
    graph.add_edge("response", "report")
    graph.add_edge("report", END)

    return graph.compile()


# ── Module-level compiled graph — built once on import ─────────────────────
compiled_graph = build_graph()


# ── Standalone test ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    from datetime import datetime, timezone
    from alerts.schemas import AlertSchema, EventType, SeverityLevel

    alert = AlertSchema(
        timestamp=datetime.now(timezone.utc),
        source_ip="185.220.101.55",
        destination_ip="192.168.1.10",
        hostname="web-server-01",
        event_type=EventType.BRUTE_FORCE,
        severity=SeverityLevel.MEDIUM,
        port=22,
        protocol="TCP",
        raw_log="sshd: 487 Failed password attempts for root from 185.220.101.55 in 30 seconds",
    )

    initial_state = {"alert": alert.model_dump(mode="json"), "errors": []}

    print("Running full pipeline...\n")
    final_state = compiled_graph.invoke(initial_state)

    print("\n" + "="*60)
    print("FINAL REPORT:")
    print(final_state["final_report"])
    print(f"\nHITL required: {final_state.get('hitl_required')}")
    print(f"Errors: {final_state.get('errors', [])}")