# evaluation/labeled_alerts.py
from alerts.schemas import EventType, SeverityLevel

# Each entry: raw_log + what a human SOC analyst WOULD label it as.
# CRITICAL: source_ip must match the IP mentioned in raw_log — otherwise
# the model correctly flags a contradiction and refuses to escalate, which
# looks like a model failure but is actually a test-data bug.

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
        "source_ip": "203.0.113.99",   # placeholder, since domain not IP appears in log
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
        "source_ip": "79.116.73.10",   # a Romania-based IP, plausible for this log
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
        "source_ip": "192.168.1.20",   # internal host, no external IP in this log type
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