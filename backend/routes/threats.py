from fastapi import APIRouter, Depends, HTTPException
from pymongo.database import Database

from database.session import get_db
from routes.logs import _to_legacy_threat
from schemas.threats import StatsResponse, Threat


router = APIRouter(prefix="/threats", tags=["threats"])


@router.get("/", response_model=list[Threat])
def list_threats(db: Database = Depends(get_db)):
    alerts = list(db.threat_alerts.find({}, {"_id": 0}).sort("created_at", -1).limit(100))
    return [_to_legacy_threat(alert) for alert in alerts]


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Database = Depends(get_db)):
    critical = db.threat_alerts.count_documents({"severity": "critical"})
    medium = db.threat_alerts.count_documents({"severity": "medium"})
    low = db.threat_alerts.count_documents({"severity": "low"})
    return StatsResponse(critical=critical, high=0, medium=medium, low=low, total=critical + medium + low)


@router.get("/{alert_id}", response_model=Threat)
def get_threat(alert_id: str, db: Database = Depends(get_db)):
    alert = db.threat_alerts.find_one({"id": alert_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found")
    return _to_legacy_threat(alert)
