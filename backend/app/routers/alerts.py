from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.models import Alert, AlertStatus, Host, User
from app.schemas.alert import AlertOut, AlertStatusUpdate

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("", response_model=list[AlertOut])
def list_alerts(
    status: AlertStatus | None = None,
    host_id: int | None = None,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    query = (
        select(Alert)
        .join(Host)
        .where(Host.user_id == user.id)
        .order_by(Alert.created_at.desc())
    )
    if status:
        query = query.where(Alert.status == status)
    if host_id:
        query = query.where(Alert.host_id == host_id)
    return db.scalars(query).all()


@router.patch("/{alert_id}", response_model=AlertOut)
def update_alert(
    alert_id: int,
    data: AlertStatusUpdate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    alert = db.scalar(
        select(Alert).join(Host).where(Alert.id == alert_id, Host.user_id == user.id)
    )
    if not alert:
        raise HTTPException(404, "Alerta no encontrada")
    alert.status = data.status
    db.commit()
    db.refresh(alert)
    return alert