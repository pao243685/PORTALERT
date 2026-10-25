from app import models
from backend.app.core.database import Base, engine

Base.metadata.create_all(engine)
print("tablas creadas")
