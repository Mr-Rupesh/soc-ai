# api/models.py
from pydantic import BaseModel
from typing import Optional, Any
from datetime import datetime


class IngestResponse(BaseModel):
    """Returned to the caller after an alert is received."""
    success:   bool
    alert_id:  str
    message:   str
    timestamp: datetime


class StatusResponse(BaseModel):
    """Health check response."""
    status:      str
    total_alerts: int
    pipeline_ready: bool


class AlertSummary(BaseModel):
    """Lightweight alert info for dashboard listing — not the full schema."""
    alert_id:   str
    event_type: str
    severity:   str
    hostname:   str
    source_ip:  str
    timestamp:  datetime
    processed:  bool        # Has it gone through the LangGraph pipeline yet?
    result:     Optional[Any] = None  # Pipeline output — None until processed