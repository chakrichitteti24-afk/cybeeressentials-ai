import csv
import io
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pymongo.database import Database

from database.session import get_db
from models.security import LogSource
from routes.logs import scan_log_batch
from schemas.logs import LogCreate
from schemas.threats import ScanResult


router = APIRouter(tags=["log converter"])


def _clean(value: Optional[str]) -> str:
    return value.strip() if isinstance(value, str) else ""


def _normalized_row(row: dict) -> dict:
    return {_clean(key).lower(): _clean(value) for key, value in row.items() if key is not None}


@router.post("/upload-csv", response_model=ScanResult)
async def upload_csv(file: UploadFile = File(...), db: Database = Depends(get_db)):
    if not (file.filename or "").lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV uploads are supported")

    try:
        content = (await file.read()).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise HTTPException(status_code=400, detail="CSV must be UTF-8 encoded") from exc

    reader = csv.DictReader(io.StringIO(content))
    headers = {_clean(header).lower() for header in (reader.fieldnames or [])}
    missing_headers = {"ip", "time", "url"} - headers
    has_status_header = "staus" in headers or "status" in headers
    if missing_headers or not has_status_header:
        required = "IP, Time, URL, Staus"
        raise HTTPException(status_code=400, detail=f"CSV must include headers: {required}")

    logs = []
    for row_number, row in enumerate(reader, start=2):
        normalized = _normalized_row(row)
        ip = normalized.get("ip", "")
        time = normalized.get("time", "")
        url = normalized.get("url", "")
        status = normalized.get("staus") or normalized.get("status", "")

        if not ip or not time or not url:
            raise HTTPException(
                status_code=400,
                detail=f"Row {row_number} must include non-empty IP, Time, and URL values",
            )

        logs.append(
            LogCreate(
                source=LogSource.web_server,
                event_type="WEB_REQUEST",
                user_id="unknown",
                source_ip=ip,
                device_id="unknown-device",
                location="Unknown",
                message=url,
                raw_event={"time": time, "status": status},
            )
        )

    if not logs:
        raise HTTPException(status_code=400, detail="CSV does not contain any data rows")

    return scan_log_batch(logs, db)
