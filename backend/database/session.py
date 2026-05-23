from functools import lru_cache

from pymongo import ASCENDING, DESCENDING, MongoClient

from database.config import get_settings


settings = get_settings()


@lru_cache
def get_client() -> MongoClient:
    return MongoClient(settings.mongodb_uri, serverSelectionTimeoutMS=5000)


def get_database():
    return get_client()[settings.mongodb_db_name]


def create_indexes() -> None:
    db = get_database()
    db.users.create_index([("email", ASCENDING)], unique=True)
    db.security_logs.create_index([("timestamp", DESCENDING)])
    db.security_logs.create_index([("source", ASCENDING), ("event_type", ASCENDING)])
    db.security_logs.create_index([("source_ip", ASCENDING)])
    db.threat_alerts.create_index([("created_at", DESCENDING)])
    db.threat_alerts.create_index([("severity", ASCENDING)])
    db.threat_alerts.create_index([("source_ip", ASCENDING)])


def get_db():
    return get_database()
