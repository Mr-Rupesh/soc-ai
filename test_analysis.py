# test_memory.py — run from soc_system/ root
from agents.memory import run_memory_agent
from datetime import datetime, timezone
from alerts.schemas import AlertSchema, EventType, SeverityLevel

# Reuse the same brute-force pattern from test_analysis.py so we KNOW
# find_similar() should match against what's already in ChromaDB.
alert = AlertSchema(
    timestamp=datetime.now(timezone.utc),
    source_ip="45.33.12.99",
    destination_ip="192.168.1.10",
    hostname="web-server-01",
    event_type=EventType.BRUTE_FORCE,
    severity=SeverityLevel.HIGH,
    port=22,
    protocol="TCP",
    raw_log="sshd: 601 Failed password attempts for admin from 45.33.12.99 in 45 seconds",
)

state = {"alert": alert.model_dump(mode="json")}

print("Running memory agent...")
result_state = run_memory_agent(state)

print("\n── Memory Summary ──")
print(result_state["memory_summary"])

print("\n── Raw Similar Incidents (for Response agent later) ──")
for inc in result_state["similar_incidents"]:
    print(inc)