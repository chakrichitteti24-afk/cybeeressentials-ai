from enum import Enum


class LogSource(str, Enum):
    authentication = "authentication"
    firewall = "firewall"
    network = "network"
    user_activity = "user_activity"
    web_server = "web_server"


class AlertSeverity(str, Enum):
    low = "low"
    medium = "medium"
    critical = "critical"
