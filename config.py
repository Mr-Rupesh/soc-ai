# config.py
from dotenv import load_dotenv
import os

load_dotenv()  # Reads .env into environment variables

# ── LLM Configuration ─────────────────────────────────────────────────────────
# Change this ONE variable to switch all agents simultaneously
PRIMARY_LLM = "groq"  # Options: "groq" | "gemini"

# Groq model assignments per agent (each agent can use a different model)
GROQ_MODELS = {
    "triage":   "llama-3.1-8b-instant",   # Fast, cheap — classification only
    "analysis": "llama-3.3-70b-versatile", # Heavy reasoning — attack identification
    "memory":   "meta-llama/llama-4-scout-17b-16e-instruct",  # Context window — similarity
    "response": "llama-3.3-70b-versatile", # Heavy reasoning — IR plan generation
    "report":   "llama-3.1-8b-instant",   # Structured output — summarization
}

# Gemini fallback (used when Groq rate-limits or PRIMARY_LLM = "gemini")
GEMINI_MODEL = "gemini-2.0-flash-lite"

# ── API Keys (loaded from .env) ────────────────────────────────────────────────
GROQ_API_KEY       = os.getenv("GROQ_API_KEY")
GOOGLE_API_KEY     = os.getenv("GOOGLE_API_KEY")
LANGSMITH_API_KEY  = os.getenv("LANGSMITH_API_KEY")
LANGSMITH_PROJECT  = os.getenv("LANGSMITH_PROJECT", "soc-ai")
OTX_API_KEY        = os.getenv("OTX_API_KEY")

# ── LangSmith Tracing (must be set before any LangChain import in other files) ─
os.environ["LANGCHAIN_TRACING_V2"]  = "true"
os.environ["LANGCHAIN_API_KEY"]     = LANGSMITH_API_KEY or ""
os.environ["LANGCHAIN_PROJECT"]     = LANGSMITH_PROJECT

# ── ChromaDB ──────────────────────────────────────────────────────────────────
CHROMA_PERSIST_DIR = "./memory/chroma_store"  # Local folder, fully free

# ── Alert Pipeline ────────────────────────────────────────────────────────────
HITL_SEVERITY_THRESHOLD = "CRITICAL"  # Only CRITICAL alerts require human approval
CONFIDENCE_THRESHOLD     = 0.75       # Below this → flag for review

# ── Sanity check (optional but useful during dev) ─────────────────────────────
if __name__ == "__main__":
    print(f"PRIMARY_LLM     : {PRIMARY_LLM}")
    print(f"GROQ key loaded : {'YES' if GROQ_API_KEY else 'NO — check .env'}")
    print(f"Gemini key      : {'YES' if GOOGLE_API_KEY else 'NO — check .env'}")
    print(f"LangSmith key   : {'YES' if LANGSMITH_API_KEY else 'NO — check .env'}")
    print(f"OTX key         : {'YES' if OTX_API_KEY else 'NO — check .env'}")