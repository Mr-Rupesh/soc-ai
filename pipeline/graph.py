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
from typing import TypedDict, Optional
from langgraph.graph import StateGraph, END

from agents.triage import run_triage
from agents.analysis import run_analysis
from agents.memory import run_memory_agent
from agents.response import run_response
from agents.report import run_report


# ── Shared State (merged from pipeline/state.py) ───────────────────────────────

class PipelineState(TypedDict):
    """
    Shared state passed through every LangGraph node.

    Design rules:
    - All fields Optional except `alert` and `errors` — agents only fill their own keys
    - Agents return PARTIAL dicts; LangGraph merges them in here automatically
    - `errors` uses list so multiple agents can append without overwriting each other
    - `alert` is a plain dict (AlertSchema.model_dump) — TypedDict can't hold Pydantic models
    """

    # ── Set at pipeline entry, never modified ─────────────────────────────────
    alert: dict                          # AlertSchema serialized — full alert data

    # ── Triage agent ──────────────────────────────────────────────────────────
    triage_severity:    Optional[str]    # May override alert's initial severity
    triage_confidence:  Optional[float]
    triage_reasoning:   Optional[str]
    triage_escalate:    Optional[bool]   # False = skip deep analysis (LOW severity)

    # ── Analysis agent ────────────────────────────────────────────────────────
    attack_type:         Optional[str]   # Human-readable: "SSH Brute Force Campaign"
    mitre_technique:     Optional[str]   # "Brute Force"
    mitre_id:            Optional[str]   # "T1110"
    otx_indicators:      Optional[list]  # Raw threat intel from AlienVault OTX
    analysis_confidence: Optional[float]
    analysis_reasoning:  Optional[str]

    # ── Memory agent ──────────────────────────────────────────────────────────
    similar_incidents:  Optional[list]   # Past alerts from ChromaDB
    memory_summary:     Optional[str]    # LLM synthesis of what history tells us

    # ── Response agent ────────────────────────────────────────────────────────
    ir_actions:          Optional[list]  # Ordered list of response steps
    hitl_required:       Optional[bool]  # True = CRITICAL, needs human approval
    hitl_approved:       Optional[bool]  # None until analyst acts
    response_confidence: Optional[float]
    response_reasoning:  Optional[str]

    # ── Report agent ──────────────────────────────────────────────────────────
    final_report:       Optional[str]    # Markdown summary written to dashboard

    # ── Pipeline metadata ─────────────────────────────────────────────────────
    errors:             list             # Any agent can append here — never overwrites
    pipeline_complete:  bool


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