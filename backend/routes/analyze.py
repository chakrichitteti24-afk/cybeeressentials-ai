from fastapi import APIRouter, Depends, HTTPException
from pymongo.database import Database

from database.session import get_db
from routes.logs import _to_legacy_threat
from schemas.threats import Threat


router = APIRouter(prefix="/analyze", tags=["analyze"])


@router.post("/{threat_id}", response_model=Threat)
def analyze(threat_id: str, db: Database = Depends(get_db)):
    alert = db.threat_alerts.find_one({"id": threat_id}, {"_id": 0})
    if not alert:
        raise HTTPException(status_code=404, detail="Threat alert not found")
    return _to_legacy_threat(alert)
