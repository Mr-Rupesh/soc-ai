# agents/analysis.py
"""
Analysis Agent — Node 2 of 5 in the LangGraph pipeline.

Job   : Identify the specific attack pattern, map it to MITRE ATT&CK, and
        enrich with real threat intel (OTX) before an analyst ever sees it.
Model : Groq Llama 3.3 70B — this needs real reasoning, not just classification.
Runs  : ONLY when triage_escalate=True (LangGraph routes around this node otherwise).
Input : state["alert"] + state["triage_*"] keys
Output: partial state dict with attack_type / mitre_* / otx_indicators / analysis_*
"""
import config  # Must be first — activates LangSmith tracing
from langchain_groq import ChatGroq
from langchain_core.prompts import ChatPromptTemplate
from pydantic import BaseModel, Field

from tools.otx_lookup import lookup_ip


# ── MITRE lookup table ──────────────────────────────────────────────────────
# WHY hardcoded, not LLM-generated:
# MITRE IDs are facts, not opinions. An LLM asked to "pick a MITRE ID" will
# occasionally hallucinate a plausible-but-wrong one (e.g. T1110 vs T1110.001).
# That corrupts any report, dashboard, or metric built on top of it, and two
# runs of the SAME alert could get two DIFFERENT IDs — unacceptable for a tool
# that's supposed to be auditable. A dict is instant, free, and deterministic.
# The LLM's job is narrower and better suited to it: naming the *specific*
# campaign in plain English and reasoning about it using OTX context.
MITRE_MAP = {
    "brute_force":           {"technique": "Brute Force",                       "id": "T1110"},
    "sql_injection":         {"technique": "Exploit Public-Facing Application", "id": "T1190"},
    "port_scan":             {"technique": "Network Service Discovery",         "id": "T1046"},
    "privilege_escalation":  {"technique": "Valid Accounts",                    "id": "T1078"},
    "data_exfiltration":     {"technique": "Exfiltration Over Web Service",     "id": "T1567"},
    "malware_detected":      {"technique": "Malicious File",                    "id": "T1204.002"},
    "phishing_attempt":      {"technique": "Phishing",                         "id": "T1566"},
    "ddos_attack":           {"technique": "Network Denial of Service",         "id": "T1498"},
    "lateral_movement":      {"technique": "Remote Services",                   "id": "T1021"},
    "unknown":               {"technique": "Unknown",                          "id": "N/A"},
}


# ── What the LLM fills in ──────────────────────────────────────────────────
# LLM does NOT touch mitre_technique/mitre_id — those come from MITRE_MAP.
# LLM only names the specific attack pattern and reasons about OTX context.
class AnalysisDecision(BaseModel):
    attack_type:      str            # e.g. "SSH Brute Force Campaign from Known Tor Exit Node"
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    reasoning:        str            # 2-3 sentences, must reference OTX verdict


ANALYSIS_PROMPT = ChatPromptTemplate.from_messages([
    ("system", """You are a SOC Tier-2 Analyst performing deep alert analysis.

You are given an alert that Tier-1 triage already escalated, plus real threat
intelligence on the source IP from AlienVault OTX.

Tasks:
1. Name the SPECIFIC attack pattern in plain English (not just the generic
   event_type — describe what's actually happening, referencing scale,
   target, or method where the data supports it).
2. Score confidence 0.0-1.0 — factor in how strongly OTX intel corroborates
   the alert (a "malicious" verdict should raise confidence; "clean"/"unknown"
   should not by itself lower it, since the OTX database has gaps).
3. Write 2-3 sentences of reasoning that explicitly mentions the OTX verdict.

Respond with ONLY a JSON object with exactly these keys: attack_type,
confidence_score, reasoning. No other keys. No markdown.
"""),
    ("human", """Security Alert (already triaged as {triage_severity}):
Event Type : {event_type}
Source IP  : {source_ip} → {destination_ip}
Hostname   : {hostname}
Port/Proto : {port} / {protocol}
Raw Log    : {raw_log}
Extra      : {extra}

OTX Threat Intel for {source_ip}:
Verdict          : {otx_verdict}
Pulse Count      : {otx_pulse_count}
Threat Types     : {otx_threat_types}
Malware Families : {otx_malware_families}
Country          : {otx_country}

Analyze this alert."""),
])


def run_analysis(state: dict) -> dict:
    """
    LangGraph calls this only when triage_escalate=True.

    Order matters: OTX lookup happens FIRST, synchronously, before the LLM
    call — the model reasons WITH threat intel already in hand rather than
    guessing about it. Same try/except fallback pattern as triage.py: if
    Groq fails, we still return the MITRE mapping (deterministic, no LLM
    needed) plus a degraded confidence, so the pipeline keeps moving.
    """
    alert  = state["alert"]
    errors = list(state.get("errors", []))

    # ── Step 1: OTX lookup (pure Python, no LLM cost) ───────────────────────
    otx_result = lookup_ip(alert["source_ip"])

    # ── Step 2: MITRE lookup (deterministic, no LLM cost) ───────────────────
    mitre = MITRE_MAP.get(alert["event_type"], MITRE_MAP["unknown"])

    # ── Step 3: LLM reasoning, enriched with OTX context ────────────────────
    try:
        llm = ChatGroq(
            model=config.GROQ_MODELS["analysis"],
            api_key=config.GROQ_API_KEY,
            temperature=0,
        ).with_structured_output(AnalysisDecision, method="json_mode")

        chain  = ANALYSIS_PROMPT | llm
        result: AnalysisDecision = chain.invoke({
            "triage_severity" : state.get("triage_severity", alert["severity"]),
            "event_type"      : alert["event_type"],
            "source_ip"       : alert["source_ip"],
            "destination_ip"  : alert["destination_ip"],
            "hostname"        : alert["hostname"],
            "port"            : alert.get("port") or "N/A",
            "protocol"        : alert.get("protocol") or "N/A",
            "raw_log"         : alert["raw_log"],
            "extra"           : alert.get("extra", {}),
            "otx_verdict"          : otx_result["verdict"],
            "otx_pulse_count"      : otx_result["pulse_count"],
            "otx_threat_types"     : otx_result["threat_types"],
            "otx_malware_families" : otx_result["malware_families"],
            "otx_country"          : otx_result["country"],
        })

        print(f"  🧠 Analysis → {result.attack_type} | "
              f"MITRE: {mitre['id']} ({mitre['technique']}) | "
              f"Confidence: {result.confidence_score:.2f}")
        print(f"     Reason  : {result.reasoning}")

        return {
            "attack_type":         result.attack_type,
            "mitre_technique":     mitre["technique"],
            "mitre_id":            mitre["id"],
            "otx_indicators":      [otx_result],
            "analysis_confidence": result.confidence_score,
            "analysis_reasoning":  result.reasoning,
        }

    except Exception as e:
        err = f"[analysis] {type(e).__name__}: {e}"
        print(f"  ❌ {err}")
        errors.append(err)

        # Graceful fallback — MITRE mapping still works (no LLM needed),
        # attack_type falls back to the raw event_type, confidence drops to 0.
        return {
            "attack_type":         alert["event_type"],
            "mitre_technique":     mitre["technique"],
            "mitre_id":            mitre["id"],
            "otx_indicators":      [otx_result],
            "analysis_confidence": 0.0,
            "analysis_reasoning":  "Analysis agent failed — using MITRE mapping only, no LLM reasoning available",
            "errors":              errors,
        }