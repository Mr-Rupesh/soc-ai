# SOC-AI

This is a project I built to learn how to actually build AI systems properly, not just call an API and print the response. It's a small pipeline of 5 AI agents that take in security alerts, figure out how serious they are, and suggest what to do about it — kind of like a mini SOC (Security Operations Center) analyst team, but automated.

This is a personal project, separate from my college work. I wanted to focus on things like: does the AI's output actually make sense, how do I check if it's right or wrong, and what happens when the AI is confidently wrong. Everything runs on free-tier APIs (Groq, ChromaDB, AlienVault OTX, LangSmith) so it costs nothing to run.

---

## Architecture

*   *

Basic flow: an alert comes in → Triage agent decides how serious it is → if serious enough, Analysis agent digs deeper and checks threat intel → Memory agent checks if we've seen something like this before → Response agent writes up an action plan → Report agent writes the final summary. If it's CRITICAL, a human has to approve before anything happens.

One thing I learned the hard way: Streamlit and LangGraph don't play nice together directly (async conflicts on Windows), so Streamlit never touches LangGraph — it only talks to FastAPI over normal HTTP requests.

---

## The 5 Agents

| Agent | Job | Model | Runs when |
|---|---|---|---|
| **Triage** | Figures out the real severity, decides if it needs escalation | `llama-3.1-8b-instant` | Every alert |
| **Analysis** | Figures out the attack type, maps it to MITRE ATT&CK, checks OTX threat intel | `llama-3.3-70b-versatile` | Only if Triage escalates |
| **Memory** | Looks up similar past incidents in ChromaDB | `gpt-oss-120b` | Every alert |
| **Response** | Writes an action plan, decides if a human needs to approve it | `llama-3.3-70b-versatile` | Every alert |
| **Report** | Puts everything together into one readable report | `llama-3.1-8b-instant` | Every alert |

Everything runs on Groq. I originally planned a Gemini fallback but dropped it — more on that below.

---

## Things I Learned / Decisions I Made

**1. `confidence_score` alone isn't enough to trust for human-review routing — I actually tested this instead of assuming.**

I built a small eval script (`evaluation/metrics.py`) with 8 alerts I labeled myself, and compared what the AI said against what I think a human analyst would say. Here's what I got:

```
SEVERITY accuracy:    4/8 (50.0%)
Avg confidence when CORRECT: 0.82
Avg confidence when WRONG:   0.80
```

The confidence score is basically the same whether the model is right or wrong. That was a bit of a wake-up call — if I'd used confidence to decide "skip human review if confidence is high," a wrong-but-confident CRITICAL alert could slip through with no human ever checking it. So instead I made the severity level itself (deterministic, not AI-guessed) the main trigger for requiring human approval, and low confidence only ever adds an extra check, never removes one.

**2. About that 50% number — I looked into why, instead of just accepting it.**

Two of the wrong ones were real misses:
- A brute-force attempt from a known bad IP (Tor exit node), 823 failed logins on root — the model called it MEDIUM, should've been HIGH.
- A textbook SQL injection payload — also called MEDIUM instead of HIGH.

The other two wrong ones are more arguable (the model's call wasn't unreasonable, just stricter/looser than what I labeled).

I think the real reason for the misses is: Triage runs *before* the OTX threat-intel lookup, which only happens later in Analysis. So Triage is judging severity without knowing "hey, this IP is known-bad" — it's working half-blind. I haven't fixed this yet, just wanted to document it honestly instead of hiding the number.

**3. MITRE ATT&CK IDs are hardcoded, not something I ask the AI to guess.**

I use a plain Python dictionary to map attack type → MITRE ID in `agents/analysis.py`, instead of letting the LLM pick one. Reason: these IDs are facts, and an LLM can occasionally guess a wrong-but-plausible one, and the same alert could get different answers on different runs. That's not something I want in a security tool. The AI's job is just to describe the attack in plain English and reason using the threat intel — that part it's actually good at.

**4. I had to switch from tool-calling to `json_mode` for structured output.**

I originally tried getting structured JSON out of Groq using tool-calling mode, but it kept throwing `tool_use_failed` errors whenever there were extra fields. Switching to `json_mode` with clear instructions in the prompt fixed it.

**5. A bug I ran into: state merging.**

LangGraph automatically merges each agent's output into the shared state. But when I wrote standalone test scripts that call agents directly (without going through the graph), I had to manually call `state.update()` myself — otherwise the next agent doesn't see the previous agent's output. Mixing these two patterns up caused a real bug while I was building the eval script.

---

## What I Deliberately Left Out

- **Gemini as a fallback LLM** — I set up a config variable for it but never actually wired the switching logic in. Rather than leave it half-built, I dropped it and just kept everything on Groq.
- **SigNoz for observability** — I considered adding this for tracking latency/token cost separately from LangSmith, but decided to keep the observability side simple with just LangSmith for now.
- **Eval coverage for Memory/Response/Report agents** — right now my eval only checks Triage and Analysis, because those have one clear right answer (severity level, attack type) to compare against. The other three agents produce open-ended text/lists, which needs a different way of checking correctness (like checking for required keywords) that I haven't built yet.

---

## Tech Stack

| Layer | Tool |
|---|---|
| Orchestration | LangGraph |
| LLM | Groq (`llama-3.1-8b-instant`, `llama-3.3-70b-versatile`, `gpt-oss-120b`) |
| Vector memory | ChromaDB (local, persistent) |
| Validation | Pydantic v2 |
| API | FastAPI |
| UI | Streamlit |
| Tracing | LangSmith |
| Threat intel | AlienVault OTX |
| Persistence | SQLite |
| Language | Python 3.13 |

---

## How to Run It

```bash
# Clone and enter the project
git clone <your-repo-url>
cd soc_system

# Create and activate a virtual environment (Windows PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
GROQ_API_KEY=your_key_here
LANGSMITH_API_KEY=your_key_here
LANGSMITH_PROJECT=soc-ai
OTX_API_KEY=your_key_here
```

You'll need 3 terminals open, in this order:

```bash
# Terminal 1 — API + pipeline
uvicorn api.main:app --reload

# Terminal 2 — Dashboard
streamlit run ui/dashboard.py

# Terminal 3 — starts sending alerts
python -c "from alerts.generator import run_generator; run_generator()"
```

Then open `http://localhost:8501` to see the dashboard.

### Running the eval

```bash
python -m evaluation.metrics
```

---

## Project Structure

```
soc_system/
├── .env
├── config.py
├── requirements.txt
├── alerts/
│   ├── schemas.py         # Normalizes all incoming alert data
│   ├── generator.py       # Makes fake alerts for testing
│   └── db.py              # SQLite storage
├── agents/
│   ├── triage.py
│   ├── analysis.py
│   ├── memory.py
│   ├── response.py
│   └── report.py
├── tools/
│   └── otx_lookup.py      # AlienVault OTX threat intel lookup
├── memory/
│   └── chromadb_manager.py
├── pipeline/
│   ├── state.py           # Shared state that flows through all agents
│   ├── graph.py            # Wires the 5 agents together
│   └── hitl.py             # Human approve/reject logic
├── api/
│   ├── main.py
│   └── models.py
├── evaluation/
│   ├── labeled_alerts.py   # My hand-labeled test cases
│   └── metrics.py          # Runs the eval, prints accuracy
└── ui/
    └── dashboard.py
```

---

## What's Next

- [ ] Fix Triage's blind spot on IP-based severity — probably by moving the OTX lookup earlier in the pipeline
- [ ] Add eval coverage for Memory/Response/Report agents
- [ ] Try LangSmith's dataset/evaluate features instead of my own hardcoded eval script
