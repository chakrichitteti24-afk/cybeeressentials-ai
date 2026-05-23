from enum import Enum


class LogSource(str, Enum):
    authentication = "authentication"
    firewall = "firewall"
    network = "network"
    user_activity = "user_activity"


class AlertSeverity(str, Enum):
    low = "low"
    medium = "medium"
    critical = "critical"
