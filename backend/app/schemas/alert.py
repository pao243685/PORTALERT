from datetime import datetime

from pydantic import BaseModel

from app.models import AlertStatus, Severity


class AlertOut(BaseModel):
    id: int
    host_id: int
    port: int | None
    title: str
    message: str
    severity: Severity
    status: AlertStatus
    confidence: str
    created_at: datetime
    model_config = {"from_attributes": True}


class AlertStatusUpdate(BaseModel):
    status: AlertStatus