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
    """
    LangGraph node. Reads `state["alert"]`, writes `state["memory_summary"]`
    and `state["similar_incidents"]` (raw list, kept for Report agent later).
    """
    alert = state["alert"]
    similar = find_similar(alert["raw_log"], n_results=3)

    if not similar:
        state["memory_summary"] = "No similar past incidents found — this is a novel pattern for this system."
        state["similar_incidents"] = []
        return state

    # Format matches into plain text for the prompt — NOT JSON, since this
    # is just context for the LLM to read, not data it needs to parse back out.
    incidents_text = "\n".join(
        f"- similarity={i['similarity']}, severity={i['severity']}, "
        f"attack_type={i['attack_type']}, false_positive={i['false_positive']}"
        for i in similar
    )

    response = _client.chat.completions.create(
        model=MEMORY_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"Current alert log: {alert['raw_log']}\n\n"
                                         f"Similar past incidents:\n{incidents_text}"},
        ],
        temperature=0.3,  # low — this is summarization, not creative reasoning
        max_tokens=150,
    )

    state["memory_summary"] = response.choices[0].message.content.strip()
    state["similar_incidents"] = similar
    print(f"  🧠 Memory: {state['memory_summary'][:80]}...")
    return state