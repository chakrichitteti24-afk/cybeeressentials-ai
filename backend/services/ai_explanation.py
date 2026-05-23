import json
from functools import lru_cache

import httpx

from database.config import get_settings
from schemas.logs import LogCreate


def _fallback_explanation(log: LogCreate, threat_type: str, risk_score: int) -> str:
    identity = f"user {log.user_id}" if log.user_id else "an unknown user"
    location = f" from {log.location}" if log.location else ""
    device = f" using device {log.device_id}" if log.device_id else ""
    return (
        f"{identity.capitalize()} triggered {log.event_type}{location}{device}. "
        f"{threat_type} indicators were detected with a risk score of {risk_score}."
    )


def _fallback_recommended_action(threat_type: str) -> str:
    actions = {
        "Brute-force attack": "Temporarily block the source IP, enforce MFA, and review account lockout policy.",
        "Credential stuffing": "Force password reset for affected accounts and check for reused credentials.",
        "Suspicious login attempt": "Verify the login with the user and revoke active sessions if unrecognized.",
        "Insider threat": "Review recent user activity, privilege changes, and sensitive data access.",
    }
    return actions.get(threat_type, "Triage the alert, enrich with context, and escalate if confirmed.")


def _groq_analysis(log: LogCreate, threat_type: str, risk_score: int) -> dict:
    settings = get_settings()
    if not settings.ai_api_key:
        return {}

    prompt = {
        "event_type": log.event_type,
        "source": log.source,
        "user_id": log.user_id,
        "source_ip": log.source_ip,
        "destination_ip": log.destination_ip,
        "device_id": log.device_id,
        "location": log.location,
        "message": log.message,
        "threat_type": threat_type,
        "risk_score": risk_score,
    }
    payload = {
        "model": settings.ai_model,
        "temperature": 0.2,
        "max_tokens": 220,
        "response_format": {"type": "json_object"},
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a SOC analyst assistant. Return only valid JSON with keys "
                    "ai_explanation and recommended_fix. Keep each value concise and human-readable."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Explain this security alert and recommend a practical response:\n"
                    f"{json.dumps(prompt, default=str)}"
                ),
            },
        ],
    }

    headers = {
        "Authorization": f"Bearer {settings.ai_api_key}",
        "Content-Type": "application/json",
    }
    response = httpx.post(settings.ai_api_url, headers=headers, json=payload, timeout=15)
    response.raise_for_status()
    content = response.json()["choices"][0]["message"]["content"]
    return json.loads(content)


def ai_status() -> dict:
    settings = get_settings()
    return {
        "provider": settings.ai_provider,
        "model": settings.ai_model,
        "api_url": settings.ai_api_url,
        "has_api_key": bool(settings.ai_api_key),
        "api_key_length": len(settings.ai_api_key or ""),
    }


@lru_cache(maxsize=128)
def _cached_ai_analysis(
    event_type: str,
    source: str,
    threat_type: str,
    risk_score: int,
    message: str,
) -> dict:
    log = LogCreate(
        source=source,
        event_type=event_type,
        message=message,
        user_id="unknown",
        device_id="unknown-device",
        location="Unknown",
    )
    return _groq_analysis(log, threat_type, risk_score)


def generate_ai_analysis(log: LogCreate, threat_type: str, risk_score: int) -> dict:
    try:
        source = log.source.value if hasattr(log.source, "value") else str(log.source)
        cache_message = log.message[:240]
        analysis = _cached_ai_analysis(log.event_type, source, threat_type, risk_score, cache_message)
    except (httpx.HTTPError, KeyError, ValueError, json.JSONDecodeError):
        analysis = {}

    return {
        "ai_explanation": analysis.get(
            "ai_explanation",
            _fallback_explanation(log, threat_type, risk_score),
        ),
        "recommended_fix": analysis.get(
            "recommended_fix",
            _fallback_recommended_action(threat_type),
        ),
    }


def generate_explanation(log: LogCreate, threat_type: str, risk_score: int) -> str:
    return generate_ai_analysis(log, threat_type, risk_score)["ai_explanation"]


def recommended_action(threat_type: str) -> str:
    return _fallback_recommended_action(threat_type)
