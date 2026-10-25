from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.deps import get_current_user
from app.core.security import generate_api_key, hash_api_key
from app.models import Host, User
from app.schemas.host import HostCreate, HostCreated, HostOut

router = APIRouter(prefix="/hosts", tags=["hosts"])


@router.post("", response_model=HostCreated, status_code=201)
def create_host(
    data: HostCreate,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key, prefix = generate_api_key()
    host = Host(
        user_id=user.id,
        name=data.name,
        os_family=data.os_family,
        api_key_prefix=prefix,
        api_key_hash=hash_api_key(key),
    )
    db.add(host)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Ya tienes un host con ese nombre")
    db.refresh(host)
    return {**HostOut.model_validate(host).model_dump(), "api_key": key}


@router.get("", response_model=list[HostOut])
def list_hosts(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.scalars(
        select(Host).where(Host.user_id == user.id).order_by(Host.name)
    ).all()


@router.delete("/{host_id}", status_code=204)
def delete_host(
    host_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    host = db.scalar(select(Host).where(Host.id == host_id, Host.user_id == user.id))
    if not host:
        raise HTTPException(404, "Host no encontrado")
    db.delete(host)
    db.commit()