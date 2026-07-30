"""
Report Agent — Node 5 of 5 in the LangGraph pipeline.

Job   : Synthesize all upstream agent outputs into one final markdown report
        for the Streamlit dashboard — this is what a human analyst reads.
Model : Groq (llama-3.1-8b-instant) — fast, cheap summarization.
Input : state["alert"] + every triage_/attack_/memory_/ir_/hitl_/response_ key
Output: partial state dict with final_report (markdown string) + pipeline_complete
"""
import config  
from groq import Groq

_client = Groq(api_key=config.GROQ_API_KEY)
REPORT_MODEL = config.GROQ_MODELS["report"]  # report summary model

REPORT_PROMPT_TEMPLATE = """You are a SOC report writer. Write a CONCISE markdown
incident report (under 200 words) from the data below. Use these exact section
headers: ## Summary, ## Severity & Classification, ## Historical Context,
## Recommended Actions, ## Human Review Status.

Be factual — do not add speculation beyond what's given. Use bullet points for
the action list.

Alert Data:
- Hostname: {hostname}
- Source IP: {source_ip}
- Event Type: {event_type}
- Triage Severity: {triage_severity} (confidence: {triage_confidence})
- Attack Type: {attack_type}
- MITRE Technique: {mitre_technique} ({mitre_id})
- Memory Summary: {memory_summary}
- IR Actions: {ir_actions}
- HITL Required: {hitl_required}
- Response Reasoning: {response_reasoning}

Write the report now."""


def run_report(state: dict) -> dict:
    """
    LangGraph node — final step. Always runs, regardless of upstream branch.
    Same try/except fallback pattern as other agents.
    """
    alert = state["alert"]
    errors = list(state.get("errors", []))

    prompt = REPORT_PROMPT_TEMPLATE.format(
        hostname          = alert["hostname"],
        source_ip         = alert["source_ip"],
        event_type        = alert["event_type"],
        triage_severity   = state.get("triage_severity", alert["severity"]),
        triage_confidence = state.get("triage_confidence", "N/A"),
        attack_type       = state.get("attack_type", "Not analyzed (below escalation threshold)"),
        mitre_technique   = state.get("mitre_technique", "N/A"),
        mitre_id          = state.get("mitre_id", "N/A"),
        memory_summary    = state.get("memory_summary", "No historical context available."),
        ir_actions        = state.get("ir_actions", ["None — alert did not require response plan"]),
        hitl_required     = state.get("hitl_required", False),
        response_reasoning= state.get("response_reasoning", "N/A"),
    )

    try:
        response = _client.chat.completions.create(
            model=REPORT_MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=400,
        )
        final_report = response.choices[0].message.content.strip()

        print(f"  📝 Report generated ({len(final_report)} chars)")

        return {
            "final_report":      final_report,
            "pipeline_complete": True,
        }

    except Exception as e:
        err = f"[report] {type(e).__name__}: {e}"
        print(f"  ❌ {err}")
        errors.append(err)

        fallback_report = f"""## Summary
Report generation failed ({type(e).__name__}). Raw data below.

## Severity & Classification
Severity: {state.get('triage_severity', alert['severity'])} | Attack: {state.get('attack_type', 'N/A')}

## Recommended Actions
{chr(10).join('- ' + a for a in state.get('ir_actions', ['Manual review required']))}

## Human Review Status
HITL Required: {state.get('hitl_required', True)}"""

        return {
            "final_report":      fallback_report,
            "pipeline_complete": True,
            "errors":            errors,
        }