# agents/response.py
"""
Response Agent — Node 4 of 5 in the LangGraph pipeline.

Job   : Generate an ordered incident-response action plan, and decide
        whether a human must approve before any action is taken (HITL).
Model : Groq Llama 3.3 70B — needs real reasoning to sequence IR steps sensibly.
Input : state["alert"], state["triage_*"], state["attack_type"/"mitre_*"],
         state["memory_summary"], state["similar_incidents"]
Output: partial state dict with ir_actions / hitl_required / response_*
"""
import config  # Must be first — activates LangSmith tracing
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field


# ── HITL gating logic ───────────────────────────────────────────────────────
# WHY severity-first, not confidence-first:
# Our eval run showed confidence_score doesn't yet separate right answers
# from wrong ones (0.82 avg when correct vs 0.80 when wrong — statistically
# not meaningful). Using it as the PRIMARY gate would be unsafe: a wrong-but-
# confident CRITICAL call could skip human review. So severity (deterministic,
# from config.HITL_SEVERITY_THRESHOLD) is the primary gate. Low confidence is
# only ever used to ADD a human check, never to remove one.
def determine_hitl(state: dict) -> bool:
    severity = state.get("triage_severity", "LOW")
    confidence = state.get("analysis_confidence", state.get("triage_confidence", 1.0))

    if severity == config.HITL_SEVERITY_THRESHOLD:  # "CRITICAL" by default
        return True
    if confidence < config.CONFIDENCE_THRESHOLD:
        return True  # low confidence → always ask a human, regardless of severity
    return False


class ResponseDecision(BaseModel):
    ir_actions:       list[str]              # ordered list, e.g. ["Isolate host", "Reset credentials"]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning:        str


RESPONSE_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a SOC Incident Response planner.

Given a triaged, analyzed security alert plus relevant history, produce an
ORDERED list of concrete incident-response actions (3-6 steps). Order matters:
containment first, then investigation, then remediation.

Score confidence 0.0-1.0 based on how clear-cut the correct response is.
Write 2-3 sentences of reasoning.

Respond with ONLY a JSON object with exactly these keys: ir_actions,
confidence_score, reasoning. No other keys. No markdown."""),
    ("human", """Alert Summary:
Event Type      : {event_type}
Triage Severity : {triage_severity}
Attack Type     : {attack_type}
MITRE Technique : {mitre_technique} ({mitre_id})
Hostname        : {hostname}
Source IP       : {source_ip}

Historical Context (from Memory agent):
{memory_summary}

Generate the incident response plan."""),
])


def run_response(state: dict) -> dict:
    """
    LangGraph node. Builds IR plan and sets hitl_required.
    Same try/except fallback pattern as Triage/Analysis — if Groq fails,
    fall back to a generic containment step and force HITL=True, since a
    fallback plan should never be auto-executed without a human looking.
    """
    alert = state["alert"]
    errors = list(state.get("errors", []))

    hitl_required = determine_hitl(state)

    try:
        llm = ChatGroq(
            model=config.GROQ_MODELS["response"],
            api_key=config.GROQ_API_KEY,
            temperature=0.2,
        ).with_structured_output(ResponseDecision, method="json_mode")

        chain = RESPONSE_PROMPT | llm
        result: ResponseDecision = chain.invoke({
            "event_type"      : alert["event_type"],
            "triage_severity" : state.get("triage_severity", alert["severity"]),
            "attack_type"     : state.get("attack_type", "unknown"),
            "mitre_technique" : state.get("mitre_technique", "unknown"),
            "mitre_id"        : state.get("mitre_id", "N/A"),
            "hostname"        : alert["hostname"],
            "source_ip"       : alert["source_ip"],
            "memory_summary"  : state.get("memory_summary", "No historical context available."),
        })

        print(f"  🛠️  Response → {len(result.ir_actions)} actions | "
              f"HITL required: {hitl_required} | Confidence: {result.confidence_score:.2f}")
        for i, action in enumerate(result.ir_actions, 1):
            print(f"     {i}. {action}")

        return {
            "ir_actions":          result.ir_actions,
            "hitl_required":       hitl_required,
            "hitl_approved":       None,  # unset until analyst acts
            "response_confidence": result.confidence_score,
            "response_reasoning":  result.reasoning,
        }

    except Exception as e:
        err = f"[response] {type(e).__name__}: {e}"
        print(f"  ❌ {err}")
        errors.append(err)

        return {
            "ir_actions":          ["Escalate to human analyst — automated response plan unavailable"],
            "hitl_required":       True,  # force human review on any failure, no exceptions
            "hitl_approved":       None,
            "response_confidence": 0.0,
            "response_reasoning":  "Response agent failed — defaulting to mandatory human review",
            "errors":              errors,
        }