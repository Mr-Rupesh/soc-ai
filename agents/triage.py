# agents/triage.py
"""
Triage Agent — Node 1 of 5 in the LangGraph pipeline.

Job   : Assess TRUE severity and decide whether this alert needs deep analysis.
Model : Groq Llama 3.1 8B — fast + cheap, classification doesn't need 70B reasoning.
Input : state["alert"] — the full AlertSchema dict
Output: partial state dict with triage_* keys filled in
"""
import config  # Must be first — activates LangSmith tracing
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field, ConfigDict
from alerts.schemas import SeverityLevel


# ── What the LLM fills in ──────────────────────────────────────────────────────
# Separate from AgentOutput intentionally:
#   - LLM fills: severity, escalate, confidence, reasoning
#   - We set:    agent_name, alert_id (don't make the LLM invent these)

class TriageDecision(BaseModel):
    model_config = ConfigDict(use_enum_values=True)
    severity:         SeverityLevel  # LLM's assessed severity — may override original
    escalate:         bool           # True → forward to Analysis agent
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning:        str            # 1-2 sentences max


# ── Prompt ─────────────────────────────────────────────────────────────────────
# System: role + rules. Human: the actual alert data.
# Keeping rules in system message means they stay outside the token window
# once we add conversation history — won't drift as alerts get longer.

TRIAGE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a SOC Tier-1 Analyst performing initial alert triage.

Tasks:
1. Assess the TRUE severity (the auto-assigned level may be wrong)
2. Set escalate=True for HIGH or CRITICAL — these need deep analysis
3. Score confidence 0.0–1.0 based on how clear-cut the alert is
4. Write 1-2 sentences of reasoning

Severity definitions:
- LOW      : Informational. No action needed.
- MEDIUM   : Monitor. May need investigation.
- HIGH     : Investigate within 1 hour. escalate=True.
- CRITICAL : immediate response required, escalate=True always.\n\n
Respond with ONLY a JSON object with exactly these keys: severity, escalate, confidence_score, reasoning. No other keys. No markdown.
"""),
    ("human", """Security Alert:
Event Type : {event_type}
Initial Severity : {severity}
Source IP  : {source_ip} → {destination_ip}
Hostname   : {hostname}
Port/Proto : {port} / {protocol}
Tags       : {tags}
Extra      : {extra}
Raw Log    : {raw_log}

Triage this alert."""),
])


# ── LangGraph node function ────────────────────────────────────────────────────
def run_triage(state: dict) -> dict:
    """
    LangGraph calls this with the full PipelineState dict.
    Returns only the keys this agent changes — LangGraph merges the rest.

    Why try/except here:
    Groq can rate-limit or timeout. If triage crashes, the pipeline shouldn't die.
    We fall back to the alert's original severity so Analysis can still run.
    """
    alert  = state["alert"]
    errors = list(state.get("errors", []))  # Copy — don't mutate state directly

    try:
        llm = ChatGroq(
            model=config.GROQ_MODELS["triage"],
            api_key=config.GROQ_API_KEY,
            temperature=0,
        ).with_structured_output(TriageDecision, method="json_mode")

        chain  = TRIAGE_PROMPT | llm
        result: TriageDecision = chain.invoke({
            "event_type"    : alert["event_type"],
            "severity"      : alert["severity"],
            "source_ip"     : alert["source_ip"],
            "destination_ip": alert["destination_ip"],
            "hostname"      : alert["hostname"],
            "port"          : alert.get("port") or "N/A",
            "protocol"      : alert.get("protocol") or "N/A",
            "tags"          : alert.get("tags", []),
            "extra"         : alert.get("extra", {}),
            "raw_log"       : alert["raw_log"],
        })

        print(f"  🔍 Triage  → {result.severity} | "
              f"Confidence: {result.confidence_score:.2f} | "
              f"Escalate: {result.escalate}")
        print(f"     Reason : {result.reasoning}")

        return {
            "triage_severity"   : result.severity,
            "triage_confidence" : result.confidence_score,
            "triage_reasoning"  : result.reasoning,
            "triage_escalate"   : result.escalate,
        }

    except Exception as e:
        err = f"[triage] {type(e).__name__}: {e}"
        print(f"  ❌ {err}")
        errors.append(err)

        # Graceful fallback — original severity, escalate HIGH/CRITICAL to be safe
        return {
            "triage_severity"   : alert["severity"],
            "triage_confidence" : 0.0,
            "triage_reasoning"  : "Triage agent failed — using original severity as fallback",
            "triage_escalate"   : alert["severity"] in ("HIGH", "CRITICAL"),
            "errors"            : errors,
        }