from sqlalchemy.orm import Session

from app.models import Host, PortEntry, ProcessEntry, Report
from app.schemas.report import ReportIn


def ingest_report(db: Session, host: Host, data: ReportIn) -> Report:
    report = Report(host_id=host.id)
    db.add(report)
    db.flush()

    by_pid = {}
    for p in data.processes:
        entry = ProcessEntry(report_id=report.id, **p.model_dump())
        db.add(entry)
        by_pid[p.pid] = entry
    db.flush()

    for p in data.ports:
        proc = by_pid.get(p.pid)
        db.add(
            PortEntry(
                report_id=report.id,
                process_id=proc.id if proc else None,
                port=p.port,
                protocol=p.protocol,
                bind_address=p.bind_address,
                service_name=p.service_name,
            )
        )
    db.flush()
    return report