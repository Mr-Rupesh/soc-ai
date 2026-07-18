# test_report.py — run from soc_system/ root
from agents.report import run_report
from datetime import datetime, timezone
from alerts.schemas import AlertSchema, EventType, SeverityLevel

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

state = {
    "alert": alert.model_dump(mode="json"),
    "triage_severity": "CRITICAL",
    "triage_confidence": 0.85,
    "attack_type": "SSH Brute Force Campaign from Known Tor Exit Node",
    "mitre_technique": "Brute Force",
    "mitre_id": "T1110",
    "analysis_confidence": 0.80,
    "memory_summary": "Similar brute-force pattern seen twice before, both classified HIGH, never marked false positive.",
    "ir_actions": [
        "Isolate web-server-01 from the network",
        "Collect and analyze SSH logs",
        "Block the known Tor exit node IP",
        "Reset potentially compromised credentials",
        "Run a vulnerability scan on the host",
    ],
    "hitl_required": True,
    "response_reasoning": "Critical severity plus known-malicious IP and repeated historical pattern.",
}

print("Running report agent...")
result_state = run_report(state)

print("\n── Final Report ──")
print(result_state["final_report"])

print(f"\nPipeline complete: {result_state['pipeline_complete']}")