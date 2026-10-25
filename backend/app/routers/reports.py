from datetime import datetime, timezone

from fastapi import APIRouter, BackgroundTasks, Depends
from sqlalchemy.orm import Session

from app.core.config import VIRUSTOTAL_API_KEY
from app.core.database import get_db
from app.core.deps import get_current_host
from app.models import Host
from app.schemas.report import ReportIn, ReportOut
from app.services.reports import ingest_report
from app.services.virustotal import consultar_y_reanalizar

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("", response_model=ReportOut, status_code=201)
def submit_report(
    data: ReportIn,
    background: BackgroundTasks,
    host: Host = Depends(get_current_host),
    db: Session = Depends(get_db),
):
    report = ingest_report(db, host, data)
    host.last_seen = datetime.now(timezone.utc)
    db.commit()
    db.refresh(report)
    if VIRUSTOTAL_API_KEY:
        background.add_task(consultar_y_reanalizar, report.id)
    return report