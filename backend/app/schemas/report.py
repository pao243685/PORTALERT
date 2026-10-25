from datetime import datetime

from pydantic import BaseModel, Field


class ProcessIn(BaseModel):
    pid: int
    name: str = Field(max_length=255)
    exe_path: str | None = None
    username: str | None = Field(default=None, max_length=100)
    sha256: str | None = Field(default=None, min_length=64, max_length=64)
    package: str | None = Field(default=None, max_length=200)
    exe_deleted: bool = False


class PortIn(BaseModel):
    port: int = Field(ge=1, le=65535)
    protocol: str = Field(max_length=10)
    bind_address: str = Field(max_length=64)
    service_name: str | None = Field(default=None, max_length=100)
    pid: int | None = None


class ReportIn(BaseModel):
    processes: list[ProcessIn] = []
    ports: list[PortIn] = []


class ReportOut(BaseModel):
    id: int
    received_at: datetime
    score: int | None
    model_config = {"from_attributes": True}