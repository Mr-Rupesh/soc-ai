import config 
from agents.triage import run_triage
from agents.analysis import run_analysis
from alerts.schemas import AlertSchema, EventType, SeverityLevel
from datetime import datetime, timezone


# ── Labeled Test Cases (merged from evaluation/labeled_alerts.py) ──────────────
# Each entry: raw_log + what a human SOC analyst WOULD label it as.

LABELED_ALERTS = [
    {
        "id": "eval_001",
        "raw_log": "sshd: 823 Failed password attempts for root from 185.220.101.55 in 60 seconds",
        "source_ip": "185.220.101.55",
        "event_type": EventType.BRUTE_FORCE,
        "true_severity": SeverityLevel.HIGH,
        "true_attack_type": "SSH Brute Force",
        "notes": "obvious — high volume, root target, known malicious IP pattern",
    },
    {
        "id": "eval_002",
        "raw_log": "Failed login for user 'jsmith' from 192.168.1.45 — 2 attempts in 10 minutes",
        "source_ip": "192.168.1.45",
        "event_type": EventType.BRUTE_FORCE,
        "true_severity": SeverityLevel.LOW,
        "true_attack_type": "Failed Login (likely benign)",
        "notes": "AMBIGUOUS — low volume, internal IP, could be user typo not attack",
    },
    {
        "id": "eval_003",
        "raw_log": "Outbound connection to known C2 domain evil-c2-server.net from host FINANCE-PC-07",
        "source_ip": "203.0.113.99",
        "event_type": EventType.MALWARE_DETECTED,
        "true_severity": SeverityLevel.CRITICAL,
        "true_attack_type": "C2 Beaconing",
        "notes": "obvious — known bad domain, should trigger HITL",
    },
    {
        "id": "eval_004",
        "raw_log": "Unusual outbound traffic volume (450MB) from DEV-LAPTOP-12 to unknown external IP 203.0.113.5 at 2:14 AM",
        "source_ip": "203.0.113.5",
        "event_type": EventType.DATA_EXFILTRATION,
        "true_severity": SeverityLevel.CRITICAL,
        "true_attack_type": "Possible Data Exfiltration",
        "notes": "AMBIGUOUS — could be legit backup job, timing is suspicious",
    },
    {
        "id": "eval_005",
        "raw_log": "User admin@company.com logged in from new location: Bucharest, Romania (previous: Mumbai, India)",
        "source_ip": "79.116.73.10",
        "event_type": EventType.UNKNOWN,
        "true_severity": SeverityLevel.MEDIUM,
        "true_attack_type": "Impossible Travel / Account Compromise",
        "notes": "AMBIGUOUS — could be VPN, could be compromised creds",
    },
    {
        "id": "eval_006",
        "raw_log": "firewall: Port scan detected from 45.33.32.156 — 4500 ports probed in 8s",
        "source_ip": "45.33.32.156",
        "event_type": EventType.PORT_SCAN,
        "true_severity": SeverityLevel.MEDIUM,
        "true_attack_type": "Port Scan / Recon",
        "notes": "obvious — clear scan signature but not yet an active breach",
    },
    {
        "id": "eval_007",
        "raw_log": "sudo: User 'svc_account' escalated privileges to root — command: chmod 777 /etc/passwd",
        "source_ip": "192.168.1.20",
        "event_type": EventType.PRIVILEGE_ESCALATION,
        "true_severity": SeverityLevel.CRITICAL,
        "true_attack_type": "Privilege Escalation",
        "notes": "obvious — service account should never touch /etc/passwd perms",
    },
    {
        "id": "eval_008",
        "raw_log": "webapp: SQL injection attempt from 198.51.100.7 — payload: SELECT * FROM users WHERE id='1' OR '1'='1'",
        "source_ip": "198.51.100.7",
        "event_type": EventType.SQL_INJECTION,
        "true_severity": SeverityLevel.HIGH,
        "true_attack_type": "SQL Injection",
        "notes": "obvious — classic injection payload",
    },
]


def run_eval():
    total = len(LABELED_ALERTS)
    severity_correct = 0
    attack_type_correct = 0

    wrong_cases = []
    confidence_on_wrong = []
    confidence_on_right = []

    for case in LABELED_ALERTS:
        alert = AlertSchema(
            timestamp=datetime.now(timezone.utc),
            source_ip=case["source_ip"],
            destination_ip="192.168.1.10",
            hostname="eval-host",
            event_type=case["event_type"],
            severity=case["true_severity"],
            port=443,
            protocol="TCP",
            raw_log=case["raw_log"],
        )

        # Replicates LangGraph's automatic state-merging behavior manually
        state = {"alert": alert.model_dump(mode="json"), "errors": []}

        triage_result = run_triage(state)
        state.update(triage_result)

        if state.get("triage_escalate"):
            analysis_result = run_analysis(state)
            state.update(analysis_result)

        predicted_severity = state.get("triage_severity")
        predicted_confidence = state.get("triage_confidence", 0.0)
        predicted_attack_type = state.get("attack_type", "N/A")

        is_severity_right = predicted_severity == case["true_severity"]
        is_attack_type_right = (
            case["true_attack_type"].split()[0].lower() in predicted_attack_type.lower()
        )

        if is_severity_right:
            severity_correct += 1
            confidence_on_right.append(predicted_confidence)
        else:
            confidence_on_wrong.append(predicted_confidence)
            wrong_cases.append({
                "id": case["id"],
                "log": case["raw_log"][:60],
                "expected": case["true_severity"],
                "got": predicted_severity,
                "confidence": predicted_confidence,
                "notes": case["notes"],
            })

        if is_attack_type_right:
            attack_type_correct += 1

    print(f"\n{'='*60}")
    print(f"SEVERITY accuracy:    {severity_correct}/{total} ({severity_correct/total*100:.1f}%)")
    print(f"ATTACK TYPE accuracy: {attack_type_correct}/{total} ({attack_type_correct/total*100:.1f}%)")

    if confidence_on_right:
        avg_right = sum(confidence_on_right) / len(confidence_on_right)
        print(f"\nAvg confidence when CORRECT: {avg_right:.2f}")
    if confidence_on_wrong:
        avg_wrong = sum(confidence_on_wrong) / len(confidence_on_wrong)
        print(f"Avg confidence when WRONG:   {avg_wrong:.2f}")
        print("^ If this is close to or higher than the 'correct' number,")
        print("  confidence_score isn't a reliable signal for HITL routing yet.")

    if wrong_cases:
        print(f"\n{'='*60}\nWRONG CASES:")
        for w in wrong_cases:
            print(f"  [{w['id']}] expected={w['expected']} got={w['got']} "
                  f"conf={w['confidence']:.2f}\n    log: {w['log']}...\n    note: {w['notes']}")


if __name__ == "__main__":
    run_eval()