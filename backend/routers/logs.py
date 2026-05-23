from fastapi import APIRouter
from typing import List
from models.schemas import LogEntry, ScanResult, Threat
from datetime import datetime
import uuid

router = APIRouter(prefix='/logs', tags=['logs'])


@router.get('/mock', response_model=List[LogEntry])
def get_mock_logs():
    now = datetime.utcnow()
    sample = [
        LogEntry(id=str(uuid.uuid4()), timestamp=now, source_ip='192.168.1.102', event_type='AUTH_FAILURE', message='Failed SSH login for user admin'),
        LogEntry(id=str(uuid.uuid4()), timestamp=now, source_ip='10.0.0.24', event_type='MALWARE_DETECTED', message='Suspicious binary execution detected in /tmp'),
        LogEntry(id=str(uuid.uuid4()), timestamp=now, source_ip='203.0.113.7', event_type='PORT_SCAN', message='Multiple TCP SYN attempts across ports 20-1024')
    ]
    return sample


@router.post('/scan', response_model=ScanResult)
def scan_logs(payload: dict):
    # Hardcoded dummy scan result
    now = datetime.utcnow().isoformat()
    threats = [
        Threat(id=str(uuid.uuid4()), severity='critical', type='Ransomware', source_ip='10.0.0.24', description='Detected a ransomware-like binary performing file encryption patterns', timestamp=now),
        Threat(id=str(uuid.uuid4()), severity='high', type='Brute Force', source_ip='192.168.1.102', description='Multiple failed SSH authentication attempts from same IP', timestamp=now),
        Threat(id=str(uuid.uuid4()), severity='medium', type='Port Scan', source_ip='203.0.113.7', description='Sequential port scan detected, likely reconnaissance', timestamp=now)
    ]
    result = ScanResult(
        total_logs=42,
        threats_found=len(threats),
        critical=1,
        high=1,
        medium=1,
        low=0,
        threats=threats
    )
    return result
