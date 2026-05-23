from pydantic import BaseModel
from typing import List
from datetime import datetime


class LogEntry(BaseModel):
    id: str
    timestamp: datetime
    source_ip: str
    event_type: str
    message: str


class Threat(BaseModel):
    id: str
    severity: str
    type: str
    source_ip: str
    description: str
    timestamp: datetime
    ai_explanation: str = ""
    recommended_fix: str = ""


class ScanResult(BaseModel):
    total_logs: int
    threats_found: int
    critical: int
    high: int
    medium: int
    low: int
    threats: List[Threat] = []


class StatsResponse(BaseModel):
    critical: int
    high: int
    medium: int
    low: int
    total: int
