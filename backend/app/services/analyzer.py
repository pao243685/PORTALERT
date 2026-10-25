from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.constants import (
    AVISO_HALLAZGOS,
    CIFRADO_TEXTO,
    DIRECCIONES_PUBLICAS,
    FACTOR_CONFIANZA,
    FRAGMENTOS_TEMPORALES,
    NIVELES,
    PREFIJOS_TEMPORALES,
    PROCESOS_DESARROLLO,
    PROCESOS_INTERMEDIARIOS,
    PUERTOS,
    PUNTOS_POR_SEVERIDAD,
    SERVICIOS_ESPERADOS,
    USUARIOS_ADMIN,
)
from app.models import (
    Alert,
    AlertStatus,
    FileReputation,
    Host,
    PortEntry,
    ProcessEntry,
    Report,
    Rule,
    Severity,
)


@dataclass
class Hallazgo:
    regla: Rule
    severidad: str
    confianza: str
    puerto: int | None
    titulo: str
    detalle: str
    recomendacion: str
    contexto: list[str] = field(default_factory=list)
    sha256: str | None = None


def _nombre(valor: str) -> str:
    nombre = valor.lower()
    return nombre[:-4] if nombre.endswith(".exe") else nombre


def _bajar(nivel: str) -> str:
    return NIVELES[max(0, NIVELES.index(nivel) - 1)]


def _es_temporal(ruta: str | None) -> bool:
    if not ruta:
        return False
    r = ruta.lower().replace("\\", "/")
    return r.startswith(PREFIJOS_TEMPORALES) or any(f in r for f in FRAGMENTOS_TEMPORALES)


def _ctx_proceso(proc: ProcessEntry) -> list[str]:
    lineas = [f"Ejecutable: {proc.exe_path or proc.name} (PID {proc.pid})"]
    if proc.username:
        lineas.append(f"Usuario: {proc.username}")
    lineas.append(f"Paquete: {proc.package or 'sin paquete asociado'}")
    lineas.append(f"Huella SHA-256: {proc.sha256 or 'no disponible'}")
    return lineas


def _ctx_puerto(port: PortEntry, proc: ProcessEntry | None) -> list[str]:
    info = PUERTOS.get(port.port)
    servicio = port.service_name or (info["servicio"] if info else "no identificado")
    cifrado = CIFRADO_TEXTO[info["cifrado"]] if info else "no determinado"
    lineas = [f"Servicio: {servicio}", f"Protocolo: {port.protocol.lower()} ({cifrado})"]
    lineas += _ctx_proceso(proc) if proc else ["Proceso: no identificado"]
    return lineas


def _por_puerto(rules: dict, port: PortEntry, proc: ProcessEntry | None) -> Hallazgo | None:
    info = PUERTOS.get(port.port)
    rule = rules.get(info["regla"]) if info else None
    if not rule:
        return None
    confianza = info["confianza"]
    if info["regla"] == "SERVIDOR_DESARROLLO":
        es_dev = proc is not None and _nombre(proc.name) in PROCESOS_DESARROLLO
        confianza = "media" if es_dev else "baja"
    return Hallazgo(
        regla=rule,
        severidad=info["severidad"],
        confianza=confianza,
        puerto=port.port,
        titulo=f"{info['servicio']} expuesto en el puerto {port.port}",
        detalle=f"{info['servicio']} escucha en {port.bind_address}:{port.port}/{port.protocol.lower()}",
        recomendacion=info["recomendacion"],
        contexto=_ctx_puerto(port, proc),
    )


def _por_nombre(rules: dict, port: PortEntry, proc: ProcessEntry | None) -> Hallazgo | None:
    rule = rules.get("PROCESO_ANOMALO")
    esperados = SERVICIOS_ESPERADOS.get(port.port)
    if not (rule and proc and esperados):
        return None
    nombre = _nombre(proc.name)
    if nombre in esperados or nombre in PROCESOS_INTERMEDIARIOS:
        return None
    return Hallazgo(
        regla=rule,
        severidad="media",
        confianza="baja" if proc.package else "media",
        puerto=port.port,
        titulo=f"Proceso inesperado en el puerto {port.port}: {proc.name}"[:200],
        detalle=f"El puerto {port.port} suele usarlo {', '.join(sorted(esperados))} y lo está usando {proc.name}",
        recomendacion="Compara la ruta y la huella del proceso con las del servicio legítimo. Si no lo reconoces, termínalo y revisa cómo llegó ahí.",
        contexto=_ctx_puerto(port, proc),
        sha256=proc.sha256,
    )


def _por_privilegios(rules: dict, port: PortEntry, proc: ProcessEntry | None) -> Hallazgo | None:
    rule = rules.get("PROCESO_ANOMALO")
    if not (rule and proc) or port.port < 1024:
        return None
    usuario = (proc.username or "").lower()
    if usuario not in USUARIOS_ADMIN or _nombre(proc.name) in PROCESOS_INTERMEDIARIOS:
        return None
    return Hallazgo(
        regla=rule,
        severidad="baja",
        confianza="media",
        puerto=port.port,
        titulo=f"Servicio con permisos de administrador en el puerto {port.port}: {proc.name}"[:200],
        detalle=f"{proc.name} corre como {proc.username} y no necesita ese privilegio para usar un puerto mayor a 1023",
        recomendacion="Ejecuta el servicio con un usuario sin privilegios creado solo para ese servicio.",
        contexto=_ctx_puerto(port, proc),
        sha256=proc.sha256,
    )


def _por_ejecutable(rules: dict, proc: ProcessEntry, con_puerto: set[int]) -> list[Hallazgo]:
    rule = rules.get("EJECUTABLE_SOSPECHOSO")
    if not rule:
        return []
    temporal = _es_temporal(proc.exe_path)
    borrado = bool(proc.exe_deleted)
    salida = []

    if temporal:
        confianza = "alta" if (proc.id in con_puerto or borrado) else "media"
        if proc.package:
            confianza = _bajar(confianza)
        salida.append(
            Hallazgo(
                regla=rule,
                severidad="alta",
                confianza=confianza,
                puerto=None,
                titulo=f"Ejecutable en ruta temporal: {proc.name}"[:200],
                detalle=f"{proc.name} se ejecuta desde {proc.exe_path}",
                recomendacion="Verifica el origen del archivo y su huella. Si no lo reconoces, termina el proceso y borra el archivo.",
                contexto=_ctx_proceso(proc),
                sha256=proc.sha256,
            )
        )

    if borrado:
        confianza = "alta" if temporal else ("baja" if proc.package else "media")
        salida.append(
            Hallazgo(
                regla=rule,
                severidad="media",
                confianza=confianza,
                puerto=None,
                titulo=f"Ejecutable eliminado del disco: {proc.name}"[:200],
                detalle=f"{proc.name} sigue en ejecución pero su archivo ya no existe",
                recomendacion="Revisa si hubo una actualización reciente de ese programa. Si no, investiga el proceso y reinícialo.",
                contexto=_ctx_proceso(proc),
                sha256=proc.sha256,
            )
        )
    return salida


def _aplicar_reputacion(h: Hallazgo, rep: FileReputation | None) -> None:
    if not rep:
        return
    if rep.status == "desconocida":
        h.contexto.append("Reputación de la huella: VirusTotal no la conoce")
        return
    h.contexto.append(
        f"Reputación de la huella: {rep.status} ({rep.malicious} de {rep.total} motores la marcan como maliciosa)"
    )
    if rep.status == "maliciosa":
        h.confianza = "alta"
    elif rep.status == "limpia" and h.regla.code in {"EJECUTABLE_SOSPECHOSO", "PROCESO_ANOMALO"}:
        h.confianza = _bajar(h.confianza)


def _por_reputacion(rules: dict, proc: ProcessEntry, rep: FileReputation | None) -> Hallazgo | None:
    rule = rules.get("EJECUTABLE_SOSPECHOSO")
    if not (rule and rep) or rep.status not in {"maliciosa", "sospechosa"}:
        return None
    maliciosa = rep.status == "maliciosa"
    recomendacion = (
        "Termina el proceso, aísla el archivo y revisa cómo llegó al equipo."
        if maliciosa
        else "Busca la huella en virustotal.com y confirma si reconoces el archivo."
    )
    return Hallazgo(
        regla=rule,
        severidad="critica" if maliciosa else "media",
        confianza="alta" if maliciosa else "media",
        puerto=None,
        titulo=f"Huella con detecciones en VirusTotal: {proc.name}"[:200],
        detalle=f"{rep.malicious} de {rep.total} motores de VirusTotal marcan como maliciosa la huella de {proc.name}",
        recomendacion=recomendacion,
        contexto=[
            *_ctx_proceso(proc),
            f"Reputación de la huella: {rep.status} ({rep.malicious} maliciosos y {rep.suspicious} sospechosos de {rep.total} motores)",
        ],
    )


def _detectar(db: Session, report: Report) -> dict:
    rules = {
        r.code: r for r in db.scalars(select(Rule).where(Rule.enabled.is_(True)))
    }
    ports = db.scalars(select(PortEntry).where(PortEntry.report_id == report.id)).all()
    procs = db.scalars(
        select(ProcessEntry).where(ProcessEntry.report_id == report.id)
    ).all()
    por_id = {p.id: p for p in procs}
    publicos = [p for p in ports if p.bind_address in DIRECCIONES_PUBLICAS]
    con_puerto = {p.process_id for p in publicos if p.process_id}

    hallazgos = []
    for port in publicos:
        proc = por_id.get(port.process_id)
        candidatos = (
            _por_puerto(rules, port, proc),
            _por_nombre(rules, port, proc),
            _por_privilegios(rules, port, proc),
        )
        hallazgos += [h for h in candidatos if h]
    for proc in procs:
        hallazgos += _por_ejecutable(rules, proc, con_puerto)

    hashes = {p.sha256 for p in procs if p.sha256}
    reputaciones = {}
    if hashes:
        reputaciones = {
            r.sha256: r
            for r in db.scalars(
                select(FileReputation).where(FileReputation.sha256.in_(hashes))
            )
        }
    for h in hallazgos:
        _aplicar_reputacion(h, reputaciones.get(h.sha256))
    for proc in procs:
        h = _por_reputacion(rules, proc, reputaciones.get(proc.sha256))
        if h:
            hallazgos.append(h)

    return {(h.regla.id, h.puerto, h.titulo): h for h in hallazgos}


def _mensaje(h: Hallazgo) -> str:
    partes = [
        f"{h.detalle}.",
        "",
        *h.contexto,
        f"Nivel de confianza: {h.confianza}",
        "",
        f"Recomendación: {h.recomendacion}",
        "",
        AVISO_HALLAZGOS,
    ]
    return "\n".join(partes)


def analyze_report(db: Session, host: Host, report: Report) -> int:
    found = _detectar(db, report)

    for (rule_id, puerto, titulo), h in found.items():
        existente = db.scalar(
            select(Alert).where(
                Alert.host_id == host.id,
                Alert.rule_id == rule_id,
                Alert.port == puerto,
                Alert.title == titulo,
                Alert.status.in_([AlertStatus.nueva, AlertStatus.ignorada]),
            )
        )
        if existente:
            existente.confidence = h.confianza
            existente.message = _mensaje(h)
            continue
        db.add(
            Alert(
                host_id=host.id,
                rule_id=rule_id,
                port=puerto,
                title=titulo,
                message=_mensaje(h),
                severity=Severity(h.severidad),
                confidence=h.confianza,
            )
        )

    penalizacion = sum(
        round(PUNTOS_POR_SEVERIDAD[h.severidad] * FACTOR_CONFIANZA[h.confianza])
        for h in found.values()
    )
    return max(0, 100 - penalizacion)