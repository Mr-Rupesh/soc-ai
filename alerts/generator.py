# alerts/generator.py
import random
import time
import requests
import json
from datetime import datetime, timezone
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from alerts.schemas import AlertSchema, SeverityLevel, EventType

# ── FastAPI target ─────────────────────────────────────────────────────────────
# This is where generator POSTs alerts to.
# FastAPI isn't built yet — generator will fail gracefully until it is.
API_URL = "http://127.0.0.1:8000/alerts/ingest"

# ── Realistic data pools ───────────────────────────────────────────────────────
# These mirror what real SOC logs look like — internal subnets, known ports, etc.

INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.45", "192.168.1.105",
    "10.0.0.5",     "10.0.0.22",    "10.0.0.87",
    "172.16.0.3",   "172.16.0.99",
]

EXTERNAL_IPS = [
    "203.0.113.42",  "198.51.100.7",  "185.220.101.55",
    "45.33.32.156",  "91.108.4.0",    "179.43.128.10",
    "5.188.206.0",   "77.88.55.60",
]

HOSTNAMES = [
    "web-server-01",   "db-server-01",    "workstation-04",
    "mail-server-02",  "vpn-gateway-01",  "fileserver-03",
    "dev-machine-07",  "admin-console-01",
]

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "SSH", "FTP", "DNS", "ICMP"]

# ── Event templates ────────────────────────────────────────────────────────────
# Each event type has: severity weights, typical ports, and a log template.
# Severity weights = [LOW, MEDIUM, HIGH, CRITICAL] — must sum to 1.0

EVENT_TEMPLATES = {
    EventType.BRUTE_FORCE: {
        "severity_weights": [0.0, 0.2, 0.5, 0.3],
        "ports":    [22, 3389, 21, 23],
        "protocol": "TCP",
        "log_template": (
            "{ts} {host} sshd: {n} Failed password attempts for root "
            "from {src} port {port} — possible brute force attack"
        ),
        "extra_keys": {"attempts": lambda: random.randint(10, 500)},
    },
    EventType.SQL_INJECTION: {
        "severity_weights": [0.0, 0.1, 0.4, 0.5],
        "ports":    [3306, 5432, 1433, 1521],
        "protocol": "TCP",
        "log_template": (
            "{ts} {host} webapp: SQL injection attempt from {src} — "
            "payload: SELECT * FROM users WHERE id='{payload}' OR '1'='1'"
        ),
        "extra_keys": {"payload_length": lambda: random.randint(50, 500)},
    },
    EventType.PORT_SCAN: {
        "severity_weights": [0.1, 0.5, 0.3, 0.1],
        "ports":    [80, 443, 8080, 8443],
        "protocol": "TCP",
        "log_template": (
            "{ts} {host} firewall: Port scan detected from {src} — "
            "{n} ports probed in {secs}s"
        ),
        "extra_keys": {
            "ports_scanned": lambda: random.randint(100, 65535),
            "scan_duration_sec": lambda: random.randint(1, 30),
        },
    },
    EventType.PRIVILEGE_ESCALATION: {
        "severity_weights": [0.0, 0.1, 0.3, 0.6],
        "ports":    [None],
        "protocol": "N/A",
        "log_template": (
            "{ts} {host} sudo: User '{user}' escalated privileges to root — "
            "command: {cmd}"
        ),
        "extra_keys": {
            "user": lambda: random.choice(["jsmith", "agarcia", "temp_user", "svc_account"]),
            "command": lambda: random.choice(["sudo su", "sudo bash", "chmod 777 /etc/passwd"]),
        },
    },
    EventType.DATA_EXFILTRATION: {
        "severity_weights": [0.0, 0.0, 0.3, 0.7],
        "ports":    [443, 80, 21, 22],
        "protocol": "HTTPS",
        "log_template": (
            "{ts} {host} DLP: Large outbound transfer to {dst} — "
            "{mb}MB sent over {mins} minutes"
        ),
        "extra_keys": {
            "mb_transferred": lambda: random.randint(100, 5000),
            "duration_min":   lambda: random.randint(1, 60),
        },
    },
    EventType.MALWARE_DETECTED: {
        "severity_weights": [0.0, 0.1, 0.4, 0.5],
        "ports":    [None],
        "protocol": "N/A",
        "log_template": (
            "{ts} {host} AV: Malware detected — file: {file} — "
            "signature: {sig} — action: quarantined"
        ),
        "extra_keys": {
            "filename": lambda: random.choice([
                "invoice_2025.exe", "update.bat", "svchost32.dll", "readme.pdf.exe"
            ]),
            "signature": lambda: random.choice([
                "Trojan.GenericKD", "Ransomware.WannaCry", "Backdoor.Cobalt"
            ]),
        },
    },
    EventType.PHISHING_ATTEMPT: {
        "severity_weights": [0.0, 0.3, 0.5, 0.2],
        "ports":    [25, 587, 465],
        "protocol": "SMTP",
        "log_template": (
            "{ts} {host} mail-filter: Phishing email blocked — "
            "from: {sender} — subject: {subj}"
        ),
        "extra_keys": {
            "sender":  lambda: random.choice([
                "noreply@paypa1.com", "security@amaz0n.net", "hr@company-fake.ru"
            ]),
            "subject": lambda: random.choice([
                "Urgent: Account Suspended", "Your package is waiting",
                "Immediate Action Required"
            ]),
        },
    },
    EventType.DDOS_ATTACK: {
        "severity_weights": [0.0, 0.1, 0.3, 0.6],
        "ports":    [80, 443, 53],
        "protocol": "UDP",
        "log_template": (
            "{ts} {host} firewall: DDoS attack detected — "
            "{pps} packets/sec from {n} source IPs — target port {port}"
        ),
        "extra_keys": {
            "packets_per_sec": lambda: random.randint(10000, 1000000),
            "source_ip_count": lambda: random.randint(100, 50000),
        },
    },
    EventType.LATERAL_MOVEMENT: {
        "severity_weights": [0.0, 0.1, 0.4, 0.5],
        "ports":    [445, 135, 139, 3389],
        "protocol": "TCP",
        "log_template": (
            "{ts} {host} EDR: Lateral movement detected — "
            "SMB connection from {src} to {dst} using stolen credentials"
        ),
        "extra_keys": {
            "credential_type": lambda: random.choice([
                "pass-the-hash", "kerberos ticket", "NTLM relay"
            ]),
        },
    },
}


def _pick_severity(weights: list[float]) -> SeverityLevel:
    """Weighted random severity — HIGH and CRITICAL appear more for dangerous events."""
    levels = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    return random.choices(levels, weights=weights, k=1)[0]


def generate_alert() -> AlertSchema:
    """
    Builds one realistic AlertSchema object.
    
    Logic:
    1. Pick a random event type from our templates
    2. Pull severity, port, IPs from that template's realistic ranges
    3. Build the log line using the template string
    4. Collect any extra fields (attempts count, file name, etc.)
    5. Return a validated AlertSchema — Pydantic catches any bad values here
    """
    event_type = random.choice(list(EVENT_TEMPLATES.keys()))
    template   = EVENT_TEMPLATES[event_type]

    severity = _pick_severity(template["severity_weights"])
    port     = random.choice(template["ports"])  # May be None for host-based events
    src_ip   = random.choice(EXTERNAL_IPS)
    dst_ip   = random.choice(INTERNAL_IPS)
    host     = random.choice(HOSTNAMES)
    ts_str   = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build the log line — each template uses different placeholders
    raw_log = template["log_template"].format(
        ts=ts_str, host=host, src=src_ip, dst=dst_ip,
        port=port or "N/A", n=random.randint(2, 999),
        secs=random.randint(1, 30), mins=random.randint(1, 60),
        mb=random.randint(100, 5000), pps=random.randint(10000, 1000000),
        user="user", cmd="sudo su", sender="phish@fake.com",
        subj="Urgent", file="malware.exe", sig="Trojan.X",
        payload="' OR '1'='1",
    )

    # Resolve extra fields — each value is a lambda, call it now
    extra = {k: fn() for k, fn in template.get("extra_keys", {}).items()}

    return AlertSchema(
        timestamp       = datetime.now(timezone.utc),
        source_ip       = src_ip,
        destination_ip  = dst_ip,
        hostname        = host,
        event_type      = event_type,
        severity        = severity,
        port            = port,
        protocol        = template["protocol"],
        raw_log         = raw_log,
        tags            = [severity.value if hasattr(severity, 'value') else severity,
                           event_type.value if hasattr(event_type, 'value') else str(event_type)],
        extra           = extra,
    )


def post_alert(alert: AlertSchema) -> bool:
    """
    Sends alert to FastAPI as JSON.
    Returns True on success, False on failure.
    Fails silently so the generator loop never crashes.
    """
    try:
        payload = alert.model_dump(mode="json")  # Pydantic V2 — serializes enums/datetimes
        response = requests.post(API_URL, json=payload, timeout=5)
        if response.status_code == 200:
            print(f"  ✅ Sent [{alert.severity}] {alert.event_type} from {alert.source_ip}")
            return True
        else:
            print(f"  ⚠️  FastAPI returned {response.status_code}: {response.text[:100]}")
            return False
    except requests.exceptions.ConnectionError:
        print(f"  ⚠️  FastAPI not running — alert not sent (this is expected until api/ is built)")
        return False
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
        return False


def run_generator(interval_sec: float = 5.0, max_alerts: int = None):
    """
    Main loop — generates and posts alerts continuously.
    
    interval_sec : seconds between alerts (default 5)
    max_alerts   : stop after N alerts (None = run forever)
    
    Use Ctrl+C to stop in terminal.
    """
    print(f"🚀 SOC-AI Alert Generator started")
    print(f"   Target  : {API_URL}")
    print(f"   Interval: {interval_sec}s")
    print(f"   Max     : {max_alerts or 'unlimited'}")
    print("─" * 50)

    count = 0
    try:
        while True:
            if max_alerts and count >= max_alerts:
                print(f"\n✅ Reached max_alerts={max_alerts}. Generator stopped.")
                break

            alert = generate_alert()
            count += 1
            print(f"\n[{count}] {datetime.now(timezone.utc).strftime('%H:%M:%S')} UTC")
            post_alert(alert)
            time.sleep(interval_sec)

    except KeyboardInterrupt:
        print(f"\n\n🛑 Generator stopped by user after {count} alerts.")


# ── Self-test (no FastAPI needed) ──────────────────────────────────────────────
if __name__ == "__main__":
    print("=== Generator self-test (no FastAPI required) ===\n")

    # Generate 3 alerts and print them — verify schema, log lines, extra fields
    for i in range(3):
        alert = generate_alert()
        print(f"Alert {i+1}:")
        print(f"  Type     : {alert.event_type}")
        print(f"  Severity : {alert.severity}")
        print(f"  Source   : {alert.source_ip} → {alert.destination_ip}")
        print(f"  Host     : {alert.hostname}")
        print(f"  Port     : {alert.port}")
        print(f"  Tags     : {alert.tags}")
        print(f"  Extra    : {alert.extra}")
        print(f"  Log      : {alert.raw_log[:80]}...")
        print()

    print("=== Self-test complete — all 3 alerts passed Pydantic validation ===")