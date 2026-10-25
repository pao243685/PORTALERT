from app import models
from app.core.database import Base, SessionLocal, engine
from app.services.rules import seed_rules

Base.metadata.create_all(engine)
print("tablas creadas")

with SessionLocal() as db:
    print(f"reglas nuevas: {seed_rules(db)}")
