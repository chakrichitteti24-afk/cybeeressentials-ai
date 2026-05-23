from fastapi import APIRouter
from models.schemas import Threat, StatsResponse
from datetime import datetime
import uuid

router = APIRouter(prefix='/threats', tags=['threats'])


@router.get('/', response_model=list[Threat])
def list_threats():
    now = datetime.utcnow().isoformat()
    threats = [
        Threat(id=str(uuid.uuid4()), severity='critical', type='Ransomware', source_ip='10.0.0.24', description='Detected a ransomware-like binary performing file encryption patterns', timestamp=now),
        Threat(id=str(uuid.uuid4()), severity='high', type='Brute Force', source_ip='192.168.1.102', description='Multiple failed SSH authentication attempts from same IP', timestamp=now),
        Threat(id=str(uuid.uuid4()), severity='low', type='Suspicious DNS', source_ip='198.51.100.5', description='Unusual DNS requests to sinkholed domains', timestamp=now)
    ]
    return threats


@router.get('/stats', response_model=StatsResponse)
def get_stats():
    return StatsResponse(critical=1, high=1, medium=0, low=1, total=3)
