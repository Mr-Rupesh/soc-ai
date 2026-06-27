# alerts/schemas.py
from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from enum import Enum
from datetime import datetime, timezone
from typing import Optional
import uuid


# ── Enums: fixed allowed values ────────────────────────────────────────────────

class SeverityLevel(str, Enum):
    """
    SOC standard severity tiers.
    Inherits from str so it serializes as "CRITICAL" not "SeverityLevel.CRITICAL".
    """
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class EventType(str, Enum):
    """
    Attack/event categories your generator produces.
    Add new types here as the system grows — agents reference these by name.
    """
    BRUTE_FORCE        = "brute_force"
    SQL_INJECTION      = "sql_injection"
    PORT_SCAN          = "port_scan"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION  = "data_exfiltration"
    MALWARE_DETECTED   = "malware_detected"
    PHISHING_ATTEMPT   = "phishing_attempt"
    DDOS_ATTACK        = "ddos_attack"
    LATERAL_MOVEMENT   = "lateral_movement"
    UNKNOWN            = "unknown"


# ── Core Alert Schema ──────────────────────────────────────────────────────────

class AlertSchema(BaseModel):
    """
    The single normalized shape every alert takes inside SOC-AI.
    generator.py creates these. All 5 agents read from this.
    FastAPI validates incoming JSON against this before the pipeline runs.
    """

    alert_id:        str           = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp:       datetime      = Field(..., description="Alert time — normalized to UTC on input")
    source_ip:       str           = Field(..., description="IP address that triggered the alert")
    destination_ip:  str           = Field(..., description="Target IP or system")
    hostname:        str           = Field(..., description="Affected host name")
    event_type:      EventType     = Field(..., description="Category of security event")
    severity:        SeverityLevel = Field(..., description="Initial severity — Triage agent may override")
    port:            Optional[int] = Field(None, ge=1, le=65535, description="Network port involved")
    protocol:        Optional[str] = Field(None, description="e.g. TCP, UDP, HTTP")
    raw_log:         str           = Field(..., description="The original log line exactly as received")
    tags:            list[str]     = Field(default_factory=list, description="Free-form labels e.g. ['internal', 'repeated']")
    extra:           dict          = Field(default_factory=dict, description="Any event-specific fields that don't fit above")

    # ── Timestamp normalizer ───────────────────────────────────────────────────
    @field_validator("timestamp", mode="before")
    @classmethod
    def normalize_to_utc(cls, v):
        """
        Accepts any of these formats and converts to UTC:
          - datetime object (with or without timezone)
          - ISO 8601 string: "2025-01-15T10:30:00+05:30"
          - Unix timestamp integer or float: 1736944200
        
        Why: generator.py may produce local timestamps. Real SIEMs send mixed formats.
        Storing everything as UTC means agent prompts are always unambiguous.
        """
        if isinstance(v, (int, float)):
            # Unix epoch → UTC datetime
            return datetime.fromtimestamp(v, tz=timezone.utc)

        if isinstance(v, str):
            # Parse ISO string — Python 3.11+ handles timezone offsets natively
            parsed = datetime.fromisoformat(v)
            if parsed.tzinfo is None:
                # Naive string (no timezone) → assume UTC
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)

        if isinstance(v, datetime):
            if v.tzinfo is None:
                return v.replace(tzinfo=timezone.utc)
            return v.astimezone(timezone.utc)

        raise ValueError(f"Cannot parse timestamp: {v!r}")

    # ── IP format check ────────────────────────────────────────────────────────
    @field_validator("source_ip", "destination_ip", mode="before")
    @classmethod
    def validate_ip(cls, v):
        """
        Basic guard — rejects obviously wrong values like empty strings.
        Not doing full RFC validation here; generator controls input anyway.
        """
        if not isinstance(v, str) or not v.strip():
            raise ValueError("IP address must be a non-empty string")
        return v.strip()

    model_config = ConfigDict(use_enum_values=True)


# ── Agent Output Base ──────────────────────────────────────────────────────────

class AgentOutput(BaseModel):
    """
    Every agent's output inherits from this.
    Enforces confidence_score from day 1 — no agent can skip it.
    
    confidence_score: 0.0 to 1.0
      - 1.0 = agent is certain
      - 0.0 = agent has no basis for its conclusion
      - Below config.CONFIDENCE_THRESHOLD → flagged for review
    """
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Agent certainty 0.0–1.0")
    reasoning:        str   = Field(..., description="Why the agent reached this conclusion")
    agent_name:       str   = Field(..., description="Which agent produced this output")


# ── Quick self-test ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Test 1: normal object creation
    alert = AlertSchema(
        timestamp="2025-01-15T10:30:00+05:30",   # IST offset → should become UTC
        source_ip="192.168.1.105",
        destination_ip="10.0.0.1",
        hostname="workstation-04",
        event_type=EventType.BRUTE_FORCE,
        severity=SeverityLevel.HIGH,
        port=22,
        protocol="TCP",
        raw_log="Jan 15 10:30:00 workstation-04 sshd: Failed password for root from 192.168.1.105"
    )
    print("✅ Alert created:")
    print(f"   ID        : {alert.alert_id}")
    print(f"   Timestamp : {alert.timestamp}  ← should be UTC")
    print(f"   Event     : {alert.event_type}")
    print(f"   Severity  : {alert.severity}")

    # Test 2: Unix timestamp input
    import time
    alert2 = AlertSchema(
        timestamp=int(time.time()),              # Unix epoch integer
        source_ip="203.0.113.42",
        destination_ip="10.0.0.5",
        hostname="db-server-01",
        event_type=EventType.SQL_INJECTION,
        severity=SeverityLevel.CRITICAL,
        raw_log="[DB] Suspicious query from 203.0.113.42: SELECT * FROM users--"
    )
    print("\n✅ Unix timestamp alert:")
    print(f"   Timestamp : {alert2.timestamp}  ← should be UTC")

    # Test 3: AgentOutput base
    output = AgentOutput(
        confidence_score=0.87,
        reasoning="Multiple failed SSH attempts within 60 seconds matches brute force pattern.",
        agent_name="triage"
    )
    print(f"\n✅ AgentOutput confidence: {output.confidence_score}")
    print("All schema tests passed.")