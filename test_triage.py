# test_triage.py  — run from soc_system/ root
import config  # MUST be first — loads LangSmith env vars before LangChain imports
from datetime import datetime, timezone
from alerts.schemas import AlertSchema, EventType, SeverityLevel
from agents.triage import run_triage

# Build a realistic alert — brute force, should come back HIGH or CRITICAL
alert = AlertSchema(
    timestamp      = datetime.now(timezone.utc),
    source_ip      = "185.220.101.55",   # Known Tor exit node IP
    destination_ip = "192.168.1.10",
    hostname       = "web-server-01",
    event_type     = EventType.BRUTE_FORCE,
    severity       = SeverityLevel.MEDIUM,   # intentionally "wrong" — should be upgraded
    port           = 22,
    protocol       = "TCP",
    raw_log        = "sshd: 487 Failed password attempts for root from 185.220.101.55 in 30 seconds",
    extra          = {"attempts": 487},
)

# Simulate what LangGraph passes to the node
state = {
    "alert"  : alert.model_dump(mode="json"),
    "errors" : [],
}

print("Running triage agent...\n")
result = run_triage(state)

print("\n── Result dict (what LangGraph would merge into state) ──")
for k, v in result.items():
    print(f"  {k}: {v}")