from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_access_token, verify_api_key
from app.models import Host, User

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    user_id = decode_access_token(token)
    user = db.get(User, user_id) if user_id else None
    if not user:
        raise HTTPException(401, "Token inválido")
    return user


def get_current_host(x_api_key: str = Header(), db: Session = Depends(get_db)) -> Host:
    prefix = x_api_key.split(".", 1)[0]
    host = db.scalar(select(Host).where(Host.api_key_prefix == prefix))
    if not host or not verify_api_key(x_api_key, host.api_key_hash):
        raise HTTPException(401, "API key inválida")
    return host