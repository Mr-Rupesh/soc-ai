# agents/memory.py
from groq import Groq
import config
from memory.chromadb_manager import find_similar

_client = Groq(api_key=config.GROQ_API_KEY)

MEMORY_MODEL = config.GROQ_MODELS["memory"]  # per your spec

SYSTEM_PROMPT = """You are a SOC memory analyst. Given a current security alert
and a list of similar past incidents, write a SHORT summary (2-3 sentences max)
answering: has this pattern occurred before, how was it classified, and was it
ever a false positive?

If no similar incidents exist, say so plainly — do not invent history.
Do not repeat raw data verbatim; synthesize it."""


def run_memory_agent(state: dict) -> dict:
    alert = state["alert"]
    similar = find_similar(alert["raw_log"], n_results=3)

    if not similar:
        return {
            "memory_summary": "No similar past incidents found — this is a novel pattern for this system.",
            "similar_incidents": [],
        }

    incidents_text = "\n".join(
        f"- similarity={i['similarity']}, severity={i['severity']}, "
        f"attack_type={i['attack_type']}, false_positive={i['false_positive']}"
        for i in similar
    )

    try:
        response = _client.chat.completions.create(
            model=MEMORY_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": f"Current alert log: {alert['raw_log']}\n\n"
                                             f"Similar past incidents:\n{incidents_text}"},
            ],
            temperature=0.3,
            max_tokens=150,
        )
        summary = response.choices[0].message.content.strip()
        print(f"  🧠 Memory: {summary[:80]}...")
        return {"memory_summary": summary, "similar_incidents": similar}

    except Exception as e:
        print(f"  ❌ [memory] {type(e).__name__}: {e}")
        return {
            "memory_summary": "Memory agent failed — no historical synthesis available.",
            "similar_incidents": similar,   # raw matches still useful even if LLM summary failed
            "errors": state.get("errors", []) + [f"[memory] {type(e).__name__}: {e}"],
        }