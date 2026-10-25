from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import REGLAS
from app.models import Rule


def seed_rules(db: Session) -> int:
    existentes = set(db.scalars(select(Rule.code)))
    nuevas = [Rule(**r) for r in REGLAS if r["code"] not in existentes]
    db.add_all(nuevas)
    db.commit()
    return len(nuevas)
