from dotenv import load_dotenv
import os

load_dotenv() 

# ── LLM Configuration ─────────────────────────────────────────────────────────
PRIMARY_LLM = "groq" 

# Groq model assignments per agent 
GROQ_MODELS = {
    "triage":   "llama-3.1-8b-instant",   # Fast, cheap — classification only
    "analysis": "llama-3.3-70b-versatile", # Heavy reasoning — attack identification
    "memory":   "openai/gpt-oss-120b",    # Context window — similarity
    "response": "llama-3.3-70b-versatile", # Heavy reasoning — IR plan generation
    "report":   "llama-3.1-8b-instant",   # Structured output — summarization
}

# ── API Keys ────────────────────────────────────────────────
GROQ_API_KEY       = os.getenv("GROQ_API_KEY")
GOOGLE_API_KEY     = os.getenv("GOOGLE_API_KEY")
LANGSMITH_API_KEY  = os.getenv("LANGSMITH_API_KEY")
LANGSMITH_PROJECT  = os.getenv("LANGSMITH_PROJECT", "soc-ai")
OTX_API_KEY        = os.getenv("OTX_API_KEY")

# ── LangSmith Tracing  ─
os.environ["LANGCHAIN_TRACING_V2"]  = "true"
os.environ["LANGCHAIN_API_KEY"]     = LANGSMITH_API_KEY or ""
os.environ["LANGCHAIN_PROJECT"]     = LANGSMITH_PROJECT

# ── ChromaDB ──────────────────────────────────────────────────────────────────
CHROMA_PERSIST_DIR = "./memory/chroma_store"  

# ── Alert Pipeline ────────────────────────────────────────────────────────────
HITL_SEVERITY_THRESHOLD = "CRITICAL"  
CONFIDENCE_THRESHOLD     = 0.75       
