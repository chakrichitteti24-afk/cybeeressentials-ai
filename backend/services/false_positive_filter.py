from schemas.logs import LogCreate


NOISE_EVENT_TYPES = {"HEALTH_CHECK", "SYSTEM_PING", "BACKUP_COMPLETED"}
KNOWN_SAFE_MESSAGES = ("scheduled vulnerability scan", "approved admin test")


def is_false_positive(log: LogCreate) -> bool:
    message = log.message.lower()
    if log.event_type.upper() in NOISE_EVENT_TYPES:
        return True
    return any(marker in message for marker in KNOWN_SAFE_MESSAGES)

