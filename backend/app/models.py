import enum
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.core.database import Base


class Severity(str, enum.Enum):
    baja = "baja"
    media = "media"
    alta = "alta"
    critica = "critica"


class AlertStatus(str, enum.Enum):
    nueva = "nueva"
    atendida = "atendida"
    ignorada = "ignorada"


SeverityType = Enum(Severity, name="severity")
AlertStatusType = Enum(AlertStatus, name="alert_status")


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    totp_secret: Mapped[str | None] = mapped_column(String(64))
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    telegram_chat_id: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    hosts: Mapped[list["Host"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Host(Base):
    __tablename__ = "hosts"
    __table_args__ = (UniqueConstraint("user_id", "name"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(100))
    os_family: Mapped[str] = mapped_column(String(20))
    api_key_prefix: Mapped[str] = mapped_column(String(12), unique=True, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(255))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    score: Mapped[int | None] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="hosts")
    reports: Mapped[list["Report"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )
    alerts: Mapped[list["Alert"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    score: Mapped[int | None] = mapped_column(Integer)

    host: Mapped["Host"] = relationship(back_populates="reports")
    ports: Mapped[list["PortEntry"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )
    processes: Mapped[list["ProcessEntry"]] = relationship(
        back_populates="report", cascade="all, delete-orphan"
    )


class ProcessEntry(Base):
    __tablename__ = "processes"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    pid: Mapped[int] = mapped_column(Integer)
    name: Mapped[str] = mapped_column(String(255))
    exe_path: Mapped[str | None] = mapped_column(Text)
    username: Mapped[str | None] = mapped_column(String(100))
    sha256: Mapped[str | None] = mapped_column(String(64), index=True)
    package: Mapped[str | None] = mapped_column(String(200))
    exe_deleted: Mapped[bool] = mapped_column(Boolean, default=False)

    report: Mapped["Report"] = relationship(back_populates="processes")


class PortEntry(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id: Mapped[int] = mapped_column(
        ForeignKey("reports.id", ondelete="CASCADE"), index=True
    )
    process_id: Mapped[int | None] = mapped_column(
        ForeignKey("processes.id", ondelete="SET NULL")
    )
    port: Mapped[int] = mapped_column(Integer, index=True)
    protocol: Mapped[str] = mapped_column(String(10))
    bind_address: Mapped[str] = mapped_column(String(64))
    service_name: Mapped[str | None] = mapped_column(String(100))

    report: Mapped["Report"] = relationship(back_populates="ports")


class Rule(Base):
    __tablename__ = "rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    code: Mapped[str] = mapped_column(String(50), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SeverityType)
    recommendation: Mapped[str] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), index=True
    )
    rule_id: Mapped[int | None] = mapped_column(
        ForeignKey("rules.id", ondelete="SET NULL")
    )
    port: Mapped[int | None] = mapped_column(Integer)
    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(SeverityType)
    status: Mapped[AlertStatus] = mapped_column(
        AlertStatusType, default=AlertStatus.nueva, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    host: Mapped["Host"] = relationship(back_populates="alerts")
