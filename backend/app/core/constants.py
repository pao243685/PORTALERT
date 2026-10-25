AVISO_HALLAZGOS = (
    "Este resultado es un indicio, no una confirmación. "
    "Ninguna interpretación de hallazgo es 100% segura."
)


DIRECCIONES_PUBLICAS = {"0.0.0.0", "::", "*"}

PREFIJOS_TEMPORALES = ("/tmp/", "/var/tmp/", "/dev/shm/")
FRAGMENTOS_TEMPORALES = ("/appdata/local/temp/", "/windows/temp/")

USUARIOS_ADMIN = {"root", "system", "nt authority\\system", "administrator"}

NIVELES = ("baja", "media", "alta")
PUNTOS_POR_SEVERIDAD = {"critica": 30, "alta": 15, "media": 8, "baja": 3}
FACTOR_CONFIANZA = {"alta": 1.0, "media": 0.6, "baja": 0.3}

CIFRADO_TEXTO = {
    True: "cifrado",
    False: "sin cifrar",
    None: "el cifrado depende de la configuración",
}

PROCESOS_INTERMEDIARIOS = {"docker-proxy", "wslrelay", "wslhost", "vpnkit", "rootlesskit"}
PROCESOS_DESARROLLO = {
    "node", "npm", "python", "python3", "uvicorn", "gunicorn",
    "flask", "vite", "php", "ruby", "deno", "bun",
}

SERVICIOS_ESPERADOS = {
    21: {"vsftpd", "proftpd", "pure-ftpd", "ftpd"},
    22: {"sshd", "dropbear"},
    23: {"telnetd", "in.telnetd", "inetd", "xinetd"},
    139: {"smbd", "nmbd", "system"},
    445: {"smbd", "system"},
    1433: {"sqlservr"},
    3306: {"mysqld", "mariadbd"},
    3389: {"xrdp", "svchost"},
    5432: {"postgres", "postmaster"},
    5900: {"x11vnc", "xvnc", "vncserver", "vino-server"},
    6379: {"redis-server"},
    9200: {"java", "elasticsearch"},
    11211: {"memcached"},
    27017: {"mongod"},
}

REC_SIN_CIFRAR = "Desactiva el servicio o cámbialo por su versión cifrada (SSH en lugar de Telnet, SFTP en lugar de FTP)."
REC_SMB = "Bloquea los puertos 139 y 445 en el firewall o límitalos a la red local."
REC_RDP = "Ponlo detrás de una VPN, activa la autenticación a nivel de red y limita el acceso por IP."
REC_VNC = "Accede por túnel SSH o VPN y usa una contraseña fuerte."
REC_SSH = "Usa llaves en lugar de contraseña, desactiva el login de root y limita por IP si es posible."
REC_BD = "Haz que escuche en 127.0.0.1 o en una red privada y limita el acceso con firewall."
REC_DEV = "Cierra el servidor al terminar de desarrollar o haz que escuche solo en 127.0.0.1."

PUERTOS = {
    21: {"regla": "SERVICIO_SIN_CIFRAR", "servicio": "FTP", "severidad": "alta", "confianza": "alta", "cifrado": False, "recomendacion": REC_SIN_CIFRAR},
    23: {"regla": "SERVICIO_SIN_CIFRAR", "servicio": "Telnet", "severidad": "critica", "confianza": "alta", "cifrado": False, "recomendacion": REC_SIN_CIFRAR},
    69: {"regla": "SERVICIO_SIN_CIFRAR", "servicio": "TFTP", "severidad": "media", "confianza": "media", "cifrado": False, "recomendacion": REC_SIN_CIFRAR},
    110: {"regla": "SERVICIO_SIN_CIFRAR", "servicio": "POP3", "severidad": "media", "confianza": "media", "cifrado": False, "recomendacion": REC_SIN_CIFRAR},
    143: {"regla": "SERVICIO_SIN_CIFRAR", "servicio": "IMAP", "severidad": "media", "confianza": "media", "cifrado": False, "recomendacion": REC_SIN_CIFRAR},
    22: {"regla": "ACCESO_REMOTO_EXPUESTO", "servicio": "SSH", "severidad": "baja", "confianza": "media", "cifrado": True, "recomendacion": REC_SSH},
    139: {"regla": "ACCESO_REMOTO_EXPUESTO", "servicio": "SMB", "severidad": "alta", "confianza": "alta", "cifrado": None, "recomendacion": REC_SMB},
    445: {"regla": "ACCESO_REMOTO_EXPUESTO", "servicio": "SMB", "severidad": "alta", "confianza": "alta", "cifrado": None, "recomendacion": REC_SMB},
    3389: {"regla": "ACCESO_REMOTO_EXPUESTO", "servicio": "Escritorio remoto (RDP)", "severidad": "alta", "confianza": "alta", "cifrado": None, "recomendacion": REC_RDP},
    5900: {"regla": "ACCESO_REMOTO_EXPUESTO", "servicio": "VNC", "severidad": "alta", "confianza": "alta", "cifrado": False, "recomendacion": REC_VNC},
}

BASES_DE_DATOS = {
    1433: "SQL Server",
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

PUERTOS_DESARROLLO = (3000, 4200, 5000, 5173, 8000, 8080, 8888)

PUERTOS.update(
    {
        p: {"regla": "BD_EXPUESTA", "servicio": nombre, "severidad": "alta", "confianza": "media", "cifrado": None, "recomendacion": REC_BD}
        for p, nombre in BASES_DE_DATOS.items()
    }
)
PUERTOS.update(
    {
        p: {"regla": "SERVIDOR_DESARROLLO", "servicio": "Servidor de desarrollo", "severidad": "media", "confianza": "baja", "cifrado": False, "recomendacion": REC_DEV}
        for p in PUERTOS_DESARROLLO
    }
)

REGLAS = [
    {
        "code": "SERVICIO_SIN_CIFRAR",
        "title": "Servicio sin cifrar expuesto",
        "description": "Telnet, FTP y otros protocolos sin cifrar escuchan en todas las interfaces, así que usuario, contraseña y datos viajan en texto plano.",
        "severity": "alta",
        "recommendation": REC_SIN_CIFRAR,
    },
    {
        "code": "ACCESO_REMOTO_EXPUESTO",
        "title": "Acceso remoto expuesto",
        "description": "Escritorio remoto, SMB, VNC o SSH escuchan en todas las interfaces y reciben intentos de acceso constantes.",
        "severity": "alta",
        "recommendation": "Limita el acceso con firewall, VPN o una lista de IP permitidas.",
    },
    {
        "code": "BD_EXPUESTA",
        "title": "Base de datos visible en toda la red",
        "description": "Una base de datos escucha en todas las interfaces y no solo en local.",
        "severity": "alta",
        "recommendation": REC_BD,
    },
    {
        "code": "SERVIDOR_DESARROLLO",
        "title": "Servidor de desarrollo abierto",
        "description": "Un servidor pensado para desarrollo escucha en todas las interfaces, normalmente sin autenticación ni endurecimiento.",
        "severity": "media",
        "recommendation": REC_DEV,
    },
    {
        "code": "EJECUTABLE_SOSPECHOSO",
        "title": "Ejecutable sospechoso",
        "description": "Un proceso corre desde una carpeta temporal o sigue activo aunque su archivo fue borrado. Es una técnica común para esconder malware.",
        "severity": "alta",
        "recommendation": "Verifica el origen del archivo y su huella antes de decidir.",
    },
    {
        "code": "PROCESO_ANOMALO",
        "title": "Proceso anómalo en un puerto",
        "description": "El proceso no coincide con el servicio esperado en ese puerto, o corre con permisos de administrador sin necesitarlos.",
        "severity": "media",
        "recommendation": "Confirma que el proceso es legítimo y ejecútalo con el mínimo de privilegios.",
    },
]

VT_URL = "https://www.virustotal.com/api/v3"
UMBRAL_MALICIOSA = 3
DIAS_VIGENCIA_REPUTACION = 7
MAX_CONSULTAS_VT = 4
PAUSA_VT_SEGUNDOS = 16