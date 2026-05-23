from schemas.logs import LogCreate


def generate_explanation(log: LogCreate, threat_type: str, risk_score: int) -> str:
    identity = f"user {log.user_id}" if log.user_id else "an unknown user"
    location = f" from {log.location}" if log.location else ""
    device = f" using device {log.device_id}" if log.device_id else ""
    return (
        f"{identity.capitalize()} triggered {log.event_type}{location}{device}. "
        f"{threat_type} indicators were detected with a risk score of {risk_score}."
    )


def recommended_action(threat_type: str) -> str:
    actions = {
        "Brute-force attack": "Temporarily block the source IP, enforce MFA, and review account lockout policy.",
        "Credential stuffing": "Force password reset for affected accounts and check for reused credentials.",
        "Suspicious login attempt": "Verify the login with the user and revoke active sessions if unrecognized.",
        "Insider threat": "Review recent user activity, privilege changes, and sensitive data access.",
    }
    return actions.get(threat_type, "Triage the alert, enrich with context, and escalate if confirmed.")

