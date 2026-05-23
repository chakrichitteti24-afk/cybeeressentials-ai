import uuid
from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends, status
from pymongo.database import Database

from database.session import get_db
from schemas.logs import LogBatchCreate, LogCreate, LogRead
from schemas.threats import ScanResult, Threat
from services.ai_explanation import generate_ai_analysis
from services.detector import detect_threat
from services.risk_scoring import severity_from_score


router = APIRouter(prefix="/logs", tags=["logs"])


def _to_legacy_threat(alert: dict) -> Threat:
    return Threat(
        id=alert["id"],
        severity=alert["severity"],
        risk_score=alert["risk_score"],
        type=alert["threat_type"],
        source_ip=alert.get("source_ip"),
        description=alert["description"],
        timestamp=alert["created_at"],
        ai_explanation=alert.get("ai_explanation", ""),
        recommended_fix=alert.get("recommended_action", ""),
    )


def _serialize_log(log: LogCreate) -> dict:
    data = log.model_dump()
    data["id"] = str(uuid.uuid4())
    data["source"] = data["source"].value if hasattr(data["source"], "value") else data["source"]
    data["created_at"] = datetime.utcnow()
    return data


def scan_log_batch(logs: List[LogCreate], db: Database) -> ScanResult:
    log_rows = [_serialize_log(log) for log in logs]
    if log_rows:
        db.security_logs.insert_many(log_rows)

    alerts = []
    for index, log in enumerate(logs):
        detection = detect_threat(log)
        if not detection:
            continue

        persisted_log = log_rows[index]
        severity = severity_from_score(detection.risk_score)
        ai_analysis = generate_ai_analysis(log, detection.threat_type, detection.risk_score)
        alert = {
            "id": str(uuid.uuid4()),
            "log_id": persisted_log["id"],
            "threat_type": detection.threat_type,
            "severity": severity.value,
            "risk_score": detection.risk_score,
            "confidence": detection.confidence,
            "source_ip": log.source_ip,
            "user_id": log.user_id,
            "description": detection.description,
            "ai_explanation": ai_analysis["ai_explanation"],
            "recommended_action": ai_analysis["recommended_fix"],
            "status": "open",
            "created_at": datetime.utcnow(),
        }
        alerts.append(alert)

    if alerts:
        db.threat_alerts.insert_many(alerts)

    threats = [_to_legacy_threat(alert) for alert in alerts]
    return ScanResult(
        total_logs=len(logs),
        threats_found=len(threats),
        critical=sum(1 for threat in threats if threat.severity == "critical"),
        high=sum(1 for threat in threats if threat.severity == "high"),
        medium=sum(1 for threat in threats if threat.severity == "medium"),
        low=sum(1 for threat in threats if threat.severity == "low"),
        threats=threats,
    )


@router.get("/mock", response_model=List[LogRead])
def get_mock_logs():
    now = datetime.utcnow()
    return [
        LogRead(
            id=str(uuid.uuid4()),
            source="authentication",
            timestamp=now,
            source_ip="192.168.1.102",
            event_type="AUTH_FAILURE",
            message="Multiple failed login attempts for user admin from an unknown device",
            raw_event={},
            created_at=now,
        ),
        LogRead(
            id=str(uuid.uuid4()),
            source="network",
            timestamp=now,
            source_ip="203.0.113.7",
            event_type="PORT_SCAN",
            message="Multiple denied TCP SYN attempts across ports 20-1024",
            raw_event={},
            created_at=now,
        ),
    ]


@router.post("/", response_model=List[LogRead], status_code=status.HTTP_201_CREATED)
def ingest_logs(payload: LogBatchCreate, db: Database = Depends(get_db)):
    rows = [_serialize_log(log) for log in payload.logs]
    if rows:
        db.security_logs.insert_many(rows)
    return rows


@router.post("/scan", response_model=ScanResult)
def scan_logs(payload: LogBatchCreate, db: Database = Depends(get_db)):
    return scan_log_batch(payload.logs, db)
