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


def _status_code(log: LogCreate) -> Optional[int]:
    try:
        return int(str(log.raw_event.get("status", "")).strip())
    except (TypeError, ValueError):
        return None


def _detect_web_request(log: LogCreate, message: str) -> Optional[Detection]:
    status = _status_code(log)
    suspicious_path_terms = (
        "/admin",
        "/adminpanel",
        "/wp-admin",
        "/phpmyadmin",
        "../",
        "%2e%2e",
        "union select",
        "<script",
        "cmd=",
        "exec=",
        "/etc/passwd",
    )
    login_terms = ("/login", "/signin", "/auth")
    failed_auth_terms = ("login.php?value=fail", "sign.php?value=fail")

    if any(term in message for term in failed_auth_terms):
        return Detection(
            threat_type="Failed web authentication",
            risk_score=45,
            confidence=0.7,
            description="Web application returned a failed login or signup marker.",
        )

    if "showcode.php" in message or "contestshowcode.php" in message:
        return Detection(
            threat_type="Sensitive source code access",
            risk_score=64,
            confidence=0.68,
            description="Request targets an endpoint that exposes submitted source code.",
        )

    if log.source_ip in {"chmod:", "rm:", "timeout:", "sh:", "a.out:"}:
        return Detection(
            threat_type="Application execution error",
            risk_score=58,
            confidence=0.66,
            description="Malformed web log row contains compiler or runtime error output.",
        )

    if any(term in message for term in suspicious_path_terms):
        return Detection(
            threat_type="Web attack attempt",
            risk_score=82 if status in {401, 403, 404} else 74,
            confidence=0.81,
            description="Web request targets a sensitive path or contains common injection/traversal indicators.",
        )

    if status in {401, 403} and any(term in message for term in login_terms):
        return Detection(
            threat_type="Suspicious web login attempt",
            risk_score=62,
            confidence=0.72,
            description="Web login request returned an authentication or authorization failure.",
        )

    if status == 403:
        return Detection(
            threat_type="Forbidden web request",
            risk_score=52,
            confidence=0.64,
            description="Web request was denied by the server and may indicate probing or blocked access.",
        )

    if status == 404 and any(term in message for term in ("admin", "config", "backup", ".env", "wp-")):
        return Detection(
            threat_type="Web reconnaissance",
            risk_score=48,
            confidence=0.62,
            description="Request for a missing sensitive resource suggests web reconnaissance.",
        )

    if status and status >= 500:
        return Detection(
            threat_type="Web server error spike",
            risk_score=44,
            confidence=0.58,
            description="Web request produced a server error that should be reviewed for exploit attempts or instability.",
        )

    return None


def detect_threat(log: LogCreate) -> Optional[Detection]:
    if is_false_positive(log):
        return None

    event_type = log.event_type.upper()
    message = log.message.lower()
    score = 10
    threat_type = "Suspicious event"
    description = log.message
    confidence = 0.45

    web_detection = _detect_web_request(log, message) if "WEB_REQUEST" in event_type else None
    if web_detection:
        return web_detection

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
