from fastapi import APIRouter
from models.schemas import Threat
from datetime import datetime

router = APIRouter(prefix='/analyze', tags=['analyze'])


@router.post('/{threat_id}', response_model=Threat)
def analyze(threat_id: str):
    now = datetime.utcnow().isoformat()
    sample = Threat(
        id=threat_id,
        severity='high',
        type='Analyzed Threat',
        source_ip='unknown',
        description='Automated analysis attached.',
        timestamp=now,
        ai_explanation='The analysis indicates repeated authentication failures and credential stuffing evidence; automated tools appear to be enumerating accounts.',
        recommended_fix='Block offending IPs, enforce MFA and account lockouts, rotate credentials, and investigate for lateral movement.'
    )
    return sample
