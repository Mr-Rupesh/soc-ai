# pipeline/state.py
from typing import TypedDict, Optional


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