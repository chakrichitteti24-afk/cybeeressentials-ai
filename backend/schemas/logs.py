from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from models.security import LogSource


class LogCreate(BaseModel):
    source: LogSource = LogSource.authentication
    event_type: str = Field(min_length=2, max_length=120)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    device_id: Optional[str] = None
    location: Optional[str] = None
    message: str = Field(min_length=1)
    raw_event: Dict[str, Any] = Field(default_factory=dict)


class LogBatchCreate(BaseModel):
    logs: List[LogCreate]


class LogRead(LogCreate):
    id: str
    created_at: datetime

    model_config = {"from_attributes": True}

