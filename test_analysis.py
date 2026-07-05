# test_analysis.py  — run from soc_system/ root
import config  # MUST be first — loads LangSmith env vars before LangChain imports
from datetime import datetime, timezone
from alerts.schemas import AlertSchema, EventType, SeverityLevel
from agents.analysis import run_analysis

# Same known Tor exit node used in otx_lookup.py's self-test —
# should return real pulse data, not a "clean"/"unknown" verdict.
alert = AlertSchema(
    timestamp      = datetime.now(timezone.utc),
    source_ip      = "185.220.101.55",
    destination_ip = "192.168.1.10",
    hostname       = "web-server-01",
    event_type     = EventType.BRUTE_FORCE,
    severity       = SeverityLevel.MEDIUM,
    port           = 22,
    protocol       = "TCP",
    raw_log        = "sshd: 487 Failed password attempts for root from 185.220.101.55 in 30 seconds",
    extra          = {"attempts": 487},
)

# Simulate state AFTER triage has already run — analysis.py reads
# triage_severity, so we set it manually here instead of calling run_triage().
state = {
    "alert"            : alert.model_dump(mode="json"),
    "triage_severity"  : "HIGH",
    "triage_confidence": 0.9,
    "triage_escalate"  : True,
    "errors"           : [],
}

print("Running analysis agent...\n")
result = run_analysis(state)

print("\n── Result dict (what LangGraph would merge into state) ──")
for k, v in result.items():
    print(f"  {k}: {v}")