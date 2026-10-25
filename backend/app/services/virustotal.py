import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import VIRUSTOTAL_API_KEY
from app.core.constants import (
    DIAS_VIGENCIA_REPUTACION,
    DIRECCIONES_PUBLICAS,
    MAX_CONSULTAS_VT,
    PAUSA_VT_SEGUNDOS,
    UMBRAL_MALICIOSA,
    VT_URL,
)
from app.core.database import SessionLocal
from app.models import FileReputation, Host, PortEntry, ProcessEntry, Report
from app.services.analyzer import _es_temporal, analyze_report


def _veredicto(malicious: int, suspicious: int) -> str:
    if malicious >= UMBRAL_MALICIOSA:
        return "maliciosa"
    if malicious or suspicious:
        return "sospechosa"
    return "limpia"


def _consultar(cliente: httpx.Client, sha256: str) -> dict | None:
    r = cliente.get(f"{VT_URL}/files/{sha256}")
    if r.status_code == 404:
        return {"status": "desconocida", "malicious": 0, "suspicious": 0, "total": 0}
    if r.status_code != 200:
        return None
    stats = r.json()["data"]["attributes"]["last_analysis_stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(
        stats.get(k, 0) for k in ("malicious", "suspicious", "undetected", "harmless")
    )
    return {
        "status": _veredicto(malicious, suspicious),
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
    }


def _hashes_pendientes(db: Session, report: Report) -> list[str]:
    procs = db.scalars(
        select(ProcessEntry).where(
            ProcessEntry.report_id == report.id, ProcessEntry.sha256.is_not(None)
        )
    ).all()
    publicos = set(
        db.scalars(
            select(PortEntry.process_id).where(
                PortEntry.report_id == report.id,
                PortEntry.bind_address.in_(DIRECCIONES_PUBLICAS),
                PortEntry.process_id.is_not(None),
            )
        )
    )
    relevantes = {
        p.sha256
        for p in procs
        if p.id in publicos or p.exe_deleted or _es_temporal(p.exe_path)
    }
    if not relevantes:
        return []
    limite = datetime.now(timezone.utc) - timedelta(days=DIAS_VIGENCIA_REPUTACION)
    vigentes = set(
        db.scalars(
            select(FileReputation.sha256).where(
                FileReputation.sha256.in_(relevantes),
                FileReputation.checked_at > limite,
            )
        )
    )
    return sorted(relevantes - vigentes)[:MAX_CONSULTAS_VT]


def _guardar(db: Session, sha256: str, datos: dict) -> None:
    fila = db.get(FileReputation, sha256) or FileReputation(sha256=sha256)
    fila.status = datos["status"]
    fila.malicious = datos["malicious"]
    fila.suspicious = datos["suspicious"]
    fila.total = datos["total"]
    fila.checked_at = datetime.now(timezone.utc)
    db.add(fila)
    db.commit()


def consultar_y_reanalizar(report_id: int) -> None:
    with SessionLocal() as db:
        report = db.get(Report, report_id)
        if not report:
            return
        pendientes = _hashes_pendientes(db, report)
        if not pendientes:
            return

        consultados = 0
        with httpx.Client(
            headers={"x-apikey": VIRUSTOTAL_API_KEY}, timeout=15
        ) as cliente:
            for i, sha256 in enumerate(pendientes):
                if i:
                    time.sleep(PAUSA_VT_SEGUNDOS)
                try:
                    datos = _consultar(cliente, sha256)
                except (httpx.HTTPError, KeyError, ValueError):
                    break
                if datos is None:
                    break
                _guardar(db, sha256, datos)
                consultados += 1

        if not consultados:
            return
        host = db.get(Host, report.host_id)
        score = analyze_report(db, host, report)
        report.score = score
        ultimo = db.scalar(select(func.max(Report.id)).where(Report.host_id == host.id))
        if ultimo == report.id:
            host.score = score
        db.commit()