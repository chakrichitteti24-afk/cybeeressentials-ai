from models.security import AlertSeverity


def severity_from_score(score: int) -> AlertSeverity:
    if score <= 30:
        return AlertSeverity.low
    if score <= 70:
        return AlertSeverity.medium
    return AlertSeverity.critical


def clamp_score(score: int) -> int:
    return max(0, min(100, score))

