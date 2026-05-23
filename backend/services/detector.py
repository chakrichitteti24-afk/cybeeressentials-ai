from dataclasses import dataclass
from typing import List, Optional

from schemas.logs import LogCreate
from services.false_positive_filter import is_false_positive
from services.risk_scoring import clamp_score


@dataclass
class Detection:
    threat_type: str
    risk_score: int
    confidence: float
    description: str


def detect_threat(log: LogCreate) -> Optional[Detection]:
    if is_false_positive(log):
        return None

    event_type = log.event_type.upper()
    message = log.message.lower()
    score = 10
    threat_type = "Suspicious event"
    description = log.message
    confidence = 0.45

    if "AUTH_FAILURE" in event_type or "failed login" in message:
        score = 78 if any(term in message for term in ["multiple", "repeated", "burst"]) else 45
        threat_type = "Brute-force attack"
        description = "Multiple failed authentication signals indicate possible brute-force activity."
        confidence = 0.82
    elif "credential" in message or "stuffing" in message:
        score = 86
        threat_type = "Credential stuffing"
        description = "Credential reuse or stuffing indicators were found in the event stream."
        confidence = 0.87
    elif "unknown device" in message or "impossible travel" in message or "new location" in message:
        score = 68
        threat_type = "Suspicious login attempt"
        description = "Login context differs from normal user behavior."
        confidence = 0.74
    elif "privilege" in message or "data export" in message or "sensitive file" in message:
        score = 80
        threat_type = "Insider threat"
        description = "User activity suggests risky privileged or sensitive data access."
        confidence = 0.79
    elif "blocked" in message or "denied" in message or "port scan" in message:
        score = 58
        threat_type = "Network reconnaissance"
        description = "Firewall or network telemetry indicates scanning or denied access attempts."
        confidence = 0.67

    if score < 31:
        return None

    return Detection(
        threat_type=threat_type,
        risk_score=clamp_score(score),
        confidence=confidence,
        description=description,
    )


def detect_threats(logs: List[LogCreate]) -> List[tuple[LogCreate, Detection]]:
    results = []
    for log in logs:
        detection = detect_threat(log)
        if detection:
            results.append((log, detection))
    return results


def detect_threats_from_text(log_text: str) -> List[dict]:
    log = LogCreate(event_type="RAW_LOG", message=log_text)
    detection = detect_threat(log)
    return [detection.__dict__] if detection else []
