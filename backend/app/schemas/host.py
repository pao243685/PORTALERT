from datetime import datetime

from pydantic import BaseModel, Field


class HostCreate(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    os_family: str = Field(min_length=1, max_length=20)


class HostOut(BaseModel):
    id: int
    name: str
    os_family: str
    last_seen: datetime
    score: int | None
    model_config = {"from_attributes": True}


class HostCreated(HostOut):
    api_key: str