from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field

from models.security import AlertSeverity


class ThreatAlertRead(BaseModel):
    id: str
    severity: AlertSeverity
    risk_score: int = Field(ge=0, le=100)
    threat_type: str
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    description: str
    timestamp: datetime
    ai_explanation: str = ""
    recommended_action: str = ""
    confidence: float = 0.0
    status: str = "open"

    model_config = {"from_attributes": True}


class Threat(BaseModel):
    id: str
    severity: str
    type: str
    source_ip: Optional[str] = None
    description: str
    timestamp: datetime
    ai_explanation: str = ""
    recommended_fix: str = ""
    risk_score: int = 0


class ScanResult(BaseModel):
    total_logs: int
    threats_found: int
    critical: int
    high: int = 0
    medium: int
    low: int
    threats: List[Threat] = []


class StatsResponse(BaseModel):
    critical: int
    high: int = 0
    medium: int
    low: int
    total: int
