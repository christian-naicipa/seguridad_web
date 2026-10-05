#!/usr/bin/env python3
"""Escáner de seguridad del SERVIDOR (VPS Ubuntu/Debian). Solo lee, no cambia nada.

Uso en el VPS:
    sudo python3 escanear_servidor.py            # recomendado: con sudo ve todo
    python3 escanear_servidor.py                 # sin sudo: algunas revisiones se omiten

Para pruebas (simula un servidor desde una carpeta):
    python3 escanear_servidor.py --raiz CARPETA --simular CARPETA/_comandos

Imprime un JSON con: hallazgos (mismo formato que escanear.py), inventario
(sistema, puertos, contenedores, apps detectadas), verificaciones_manuales y notas.
"""
import argparse
import datetime
import glob
import json
import os
import re
import subprocess
import sys

SEVERIDADES = ["critica", "alta", "media", "baja", "info"]

PUERTOS_BD = {5432: "PostgreSQL", 3306: "MySQL/MariaDB", 27017: "MongoDB", 6379: "Redis", 9200: "Elasticsearch",
              5984: "CouchDB", 11211: "Memcached", 8086: "InfluxDB", 1433: "SQL Server", 7474: "Neo4j",
              6333: "Qdrant", 8123: "ClickHouse", 9042: "Cassandra", 5672: "RabbitMQ"}
PUERTOS_PANEL = {2375: "API de Docker sin cifrar", 2376: "API de Docker", 5678: "n8n", 9000: "Portainer/MinIO",
                 9443: "Portainer", 8000: "Coolify", 3000: "EasyPanel/app", 10000: "Webmin", 8888: "Jupyter",
                 9090: "Cockpit/Prometheus", 15672: "RabbitMQ (panel)", 5601: "Kibana", 8080: "panel/app",
                 8081: "panel/app", 8443: "panel", 3001: "Uptime Kuma/app", 19999: "Netdata",
                 6443: "Kubernetes API", 2019: "API de Caddy", 7700: "Meilisearch", 54321: "Supabase local",
                 5050: "pgAdmin", 8090: "PocketBase/panel", 1880: "Node-RED", 3030: "app"}
PUERTOS_WEB = {80, 443}
GESTORES_DOCKER = re.compile(r"portainer|coolify|traefik|easypanel|watchtower|caddy|nginx-proxy|dockge|dozzle|"
                             r"cadvisor|promtail|alloy|komodo|dokploy|cosmos|yacht|autoheal|diun", re.I)
MINEROS = re.compile(r"xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|xmr-stak|nanominer|c3pool|supportxmr|nanopool|"
                     r"stratum\+tcp|stratum\+ssl|cryptonight|\.xm\b|/dev/shm/\.|/tmp/\.", re.I)
CRON_MALO = re.compile(r"(curl|wget)[^|;\n]*\|\s*(ba|da|z)?sh\b|base64\s+(-d|--decode)|/dev/tcp/|"
                       r"\s/tmp/[^\s]*|\s/dev/shm/|\s/var/tmp/[^\s]*|python[0-9.]*\s+-c\s+['\"]import\s+(socket|os)", re.I)
BACKUP = re.compile(r"pg_dump|pg_dumpall|mysqldump|mariadb-dump|mongodump|restic|borg|rclone|duplicati|duplicity|"
                    r"kopia|backup|respaldo|snapshot|rsnapshot|autorestic", re.I)
DIRS_APPS = ["/var/www", "/opt", "/srv", "/home", "/root", "/var/lib/docker/volumes"]
MARCAS_APP = ("package.json", "composer.json", "requirements.txt", "pyproject.toml", "Gemfile", "go.mod",
              "next.config.js", "next.config.mjs", "next.config.ts", "wp-config.php", "docker-compose.yml",
              "docker-compose.yaml", "compose.yml", "compose.yaml", "manage.py", "artisan")
IGNORAR_DIRS = {"node_modules", ".git", ".next", "dist", "build", "vendor", "__pycache__", ".cache", ".npm",
                ".local", ".config", ".vscode-server", ".cursor-server", "snap", ".nvm", ".pm2", ".docker", "go"}


class Sistema:
    """Acceso al servidor: real o simulado (para pruebas)."""

    def __init__(self, raiz="/", simular=None):
        self.raiz = os.path.abspath(raiz)
        self.simular = simular
        if simular:
            self.es_root = not os.path.exists(os.path.join(simular, "_sin_root"))
        else:
            self.es_root = hasattr(os, "geteuid") and os.geteuid() == 0

    def ruta(self, p):
        return os.path.join(self.raiz, p.lstrip("/")) if self.raiz != "/" else p

    def leer(self, p, limite=2_000_000):
        try:
            with open(self.ruta(p), "r", encoding="utf-8", errors="ignore") as f:
                return f.read(limite)
        except (OSError, IOError):
            return None

    def existe(self, p):
        return os.path.exists(self.ruta(p))

    def glob(self, patron):
        res = glob.glob(self.ruta(patron))
        if self.raiz == "/":
            return sorted(res)
        return sorted("/" + os.path.relpath(r, self.raiz) for r in res)

    def cmd(self, clave, args, combinar=False):
        """Ejecuta un comando de solo lectura. Devuelve la salida o None si no existe/falla."""
        if self.simular:
            try:
                with open(os.path.join(self.simular, clave + ".txt"), encoding="utf-8") as f:
                    return f.read()
            except OSError:
                return None
        try:
            r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=25,
                               shell=isinstance(args, str))
        except Exception:
            return None
        if r.returncode == 127:
            return None
        salida = r.stdout + (r.stderr if combinar else "")
        if r.returncode != 0 and not salida.strip():
            return None
        return salida

    def caminar(self, base, profundidad, ocultos=False):
        """os.walk limitado en profundidad. Devuelve rutas del servidor (no de la raíz local)."""
        real = self.ruta(base)
        if not os.path.isdir(real):
            return
        base_n = real.rstrip(os.sep).count(os.sep)
        for dirpath, dirnames, filenames in os.walk(real):
            nivel = dirpath.rstrip(os.sep).count(os.sep) - base_n
            dirnames[:] = [d for d in dirnames if d not in IGNORAR_DIRS and (ocultos or not d.startswith("."))]
            if nivel >= profundidad:
                dirnames[:] = []
            servidor = dirpath if self.raiz == "/" else "/" + os.path.relpath(dirpath, self.raiz)
            yield servidor.replace(os.sep, "/"), dirnames, filenames

    def modo(self, p):
        try:
            return os.stat(self.ruta(p)).st_mode
        except OSError:
            return None


class EscanerServidor:
    def __init__(self, sistema):
        self.s = sistema
        self.hallazgos = []
        self.manuales = []
        self.notas = []
        self.omitidas = []
        self.inv = {"sistema": {}, "puertos_publicos": [], "contenedores": [], "apps_detectadas": [],
                    "llaves_ssh_autorizadas": [], "firewall": None}
        self.firewall_activo = None
        self.ufw_permitidos = set()
        self.ufw_permite_todo = False

    def agregar(self, regla, severidad, confianza, titulo, donde=None, evidencia=None, detalle="", puerto=None):
        h = {"regla": regla, "severidad": severidad, "confianza": confianza, "titulo": titulo,
             "archivo": donde, "linea": None, "evidencia": evidencia, "detalle": detalle, "grupo": "servidor"}
        if puerto is None and donde:
            m = re.match(r"puerto (\d+)$", str(donde))
            puerto = int(m.group(1)) if m else None
        if puerto is not None:
            h["puerto"] = puerto
        self.hallazgos.append(h)

    def omitir(self, que):
        if que not in self.omitidas:
            self.omitidas.append(que)

    # ------------------------------------------------------------------ sistema
    def revisar_sistema(self):
        osr = self.s.leer("/etc/os-release") or ""
        m = re.search(r'^PRETTY_NAME="?([^"\n]+)', osr, re.M)
        self.inv["sistema"]["os"] = m.group(1) if m else "desconocido"
        m = re.search(r'^VERSION_ID="?([\d.]+)', osr, re.M)
        ident = re.search(r'^ID=("?)(\w+)', osr, re.M)
        if m and ident:
            nombre, ver = ident.group(2), m.group(1)
            fin_soporte = {"ubuntu": {"16.04": 2021, "18.04": 2023, "20.04": 2025, "21.04": 2022, "21.10": 2022,
                                      "22.10": 2023, "23.04": 2024, "23.10": 2024, "24.10": 2025},
                           "debian": {"9": 2022, "10": 2024}}
            anio = fin_soporte.get(nombre, {}).get(ver)
            if anio and anio <= datetime.date.today().year:
                self.agregar("SO_SIN_SOPORTE", "alta", "confirmado",
                             "El sistema operativo ya no recibe parches de seguridad (%s)" % self.inv["sistema"]["os"],
                             "/etc/os-release", self.inv["sistema"]["os"],
                             "Las fallas nuevas que se descubran no se van a arreglar. Hay que migrar a una versión con soporte "
                             "(por ejemplo Ubuntu 24.04 LTS), idealmente en un VPS nuevo.")
        df = self.s.cmd("df", ["df", "-P", "/"])
        if df:
            m = re.search(r"(\d+)%\s+/\s*$", df, re.M)
            if m:
                uso = int(m.group(1))
                self.inv["sistema"]["disco_usado"] = "%d%%" % uso
                if uso >= 90:
                    self.agregar("DISCO_LLENO", "media", "confirmado", "El disco está al %d%%" % uso, "/", None,
                                 "Con el disco lleno la base de datos y la app dejan de funcionar y no se guardan logs ni backups.")

    # --------------------------------------------------------------- firewall
    def revisar_firewall(self):
        ufw = self.s.cmd("ufw", ["ufw", "status"], combinar=True)
        if ufw and re.search(r"Status:\s*active|Estado:\s*activo", ufw, re.I):
            self.firewall_activo = True
            self.inv["firewall"] = "ufw activo"
            for linea in ufw.splitlines():
                m = re.match(r"\s*(\d+)(?::(\d+))?(?:/(tcp|udp))?\s+(ALLOW|LIMIT)", linea, re.I)
                if m:
                    a = int(m.group(1))
                    b = int(m.group(2) or a)
                    self.ufw_permitidos.update(range(a, b + 1))
                elif re.match(r"\s*Anywhere\s+ALLOW", linea, re.I):
                    self.ufw_permite_todo = True
                else:
                    m2 = re.match(r"\s*([A-Za-z][\w ]+?)\s+(ALLOW|LIMIT)", linea)
                    if m2 and m2.group(1).strip().lower() in ("openssh", "nginx full", "nginx http", "nginx https",
                                                              "apache full", "www full"):
                        n = m2.group(1).strip().lower()
                        self.ufw_permitidos.update({22} if n == "openssh" else {80, 443})
            return
        if ufw is None and not self.s.es_root:
            self.omitir("firewall (ufw status necesita sudo)")
        nft = self.s.cmd("nft", ["nft", "list", "ruleset"])
        ipt = self.s.cmd("iptables", ["iptables", "-S", "INPUT"])
        if (nft and re.search(r"hook input[^}]*policy drop", nft, re.S)) or (ipt and "-P INPUT DROP" in ipt):
            self.firewall_activo = True
            self.inv["firewall"] = "nftables/iptables con política DROP"
            return
        if ufw is None and nft is None and ipt is None:
            if self.s.es_root:
                self.firewall_activo = False
            return
        self.firewall_activo = False
        self.inv["firewall"] = "inactivo"
        self.agregar("FIREWALL_INACTIVO", "alta", "confirmado", "El firewall del servidor está apagado", "ufw status",
                     (ufw or "").strip().splitlines()[0] if ufw else None,
                     "Cualquier programa que abra un puerto queda expuesto a internet. Puede que tu proveedor (Hetzner, "
                     "DigitalOcean, AWS) tenga un firewall propio: revísalo en su panel.")

    # ---------------------------------------------------------------- puertos
    def revisar_puertos(self):
        ss = self.s.cmd("ss", ["ss", "-tlnpH"])
        if ss is None:
            ss = self.s.cmd("netstat", ["netstat", "-tlnp"])
        if ss is None:
            self.omitir("puertos abiertos (no hay ss ni netstat)")
            return
        vistos = {}
        for linea in ss.splitlines():
            partes = linea.split()
            if len(partes) < 4:
                continue
            local = None
            for p in partes:
                if re.match(r"^(\[?[0-9a-fA-F:.*%\w]*\]?):(\d+)$", p) and not p.endswith(":*"):
                    local = p
                    break
            if not local:
                continue
            host, puerto = local.rsplit(":", 1)
            host = host.strip("[]").split("%")[0]
            puerto = int(puerto)
            if host in ("127.0.0.1", "::1", "localhost") or host.startswith("127.") or host.startswith("fe80"):
                continue
            proc = re.search(r'users:\(\("([^"]+)"', linea)
            proc = proc.group(1) if proc else (partes[-1] if "/" in partes[-1] else "?")
            if puerto in vistos:
                continue
            vistos[puerto] = proc
        for puerto, proc in sorted(vistos.items()):
            self.inv["puertos_publicos"].append({"puerto": puerto, "proceso": proc})
            por_docker = "docker" in proc
            permitido = self.ufw_permite_todo or puerto in self.ufw_permitidos
            if por_docker:
                continue  # lo evalúa revisar_docker (Docker se salta ufw)
            if puerto == 2375:
                self.agregar("DOCKER_API_EXPUESTA", "critica", "confirmado",
                             "La API de Docker está abierta sin contraseña (puerto 2375)", "puerto 2375", proc,
                             "Quien se conecte controla el servidor completo (puede crear contenedores con acceso a todo el disco).")
                continue
            nombre = PUERTOS_BD.get(puerto) or PUERTOS_PANEL.get(puerto)
            if not nombre:
                continue
            es_bd = puerto in PUERTOS_BD
            if self.firewall_activo is False or permitido:
                sev = "critica" if es_bd else "alta"
                self.agregar("BD_EXPUESTA" if es_bd else "PANEL_EXPUESTO", sev, "revisar",
                             "%s está abierto a internet (puerto %d)" % (nombre, puerto), "puerto %d" % puerto, proc,
                             ("Las bases de datos abiertas a internet son la causa número uno de datos robados o "
                              "secuestrados (borran todo y piden rescate). Debe escuchar solo en 127.0.0.1." if es_bd else
                              "Los bots buscan estos paneles todo el día. Debe estar detrás de login fuerte o solo accesible "
                              "por túnel SSH/VPN."))
            elif self.firewall_activo:
                self.agregar("BD_ESCUCHA_PUBLICA" if es_bd else "PANEL_ESCUCHA_PUBLICA", "baja", "revisar",
                             "%s escucha en todas las interfaces, pero el firewall lo bloquea (puerto %d)" % (nombre, puerto),
                             "puerto %d" % puerto, proc,
                             "Hoy está protegido por el firewall. Si alguien lo desactiva, queda expuesto: mejor que escuche solo en 127.0.0.1.")

    # ----------------------------------------------------------------- docker
    def revisar_docker(self):
        ps = self.s.cmd("docker_ps", ["docker", "ps", "--format", "{{.Names}}\t{{.Image}}\t{{.Ports}}"])
        if ps is None:
            if self.s.cmd("docker_version", ["docker", "--version"]) and not self.s.es_root:
                self.omitir("contenedores Docker (necesita sudo)")
            return
        for linea in ps.strip().splitlines():
            partes = linea.split("\t")
            if len(partes) < 2:
                continue
            nombre, imagen = partes[0], partes[1]
            puertos = partes[2] if len(partes) > 2 else ""
            self.inv["contenedores"].append({"nombre": nombre, "imagen": imagen, "puertos": puertos})
            vistos = set()
            for m in re.finditer(r"(0\.0\.0\.0|\[?::\]?):(\d+)(?:-(\d+))?->(\d+)", puertos):
                host_p = int(m.group(2))
                cont_p = int(m.group(4))
                if host_p in vistos:
                    continue  # el mismo puerto publicado en IPv4 e IPv6
                vistos.add(host_p)
                servicio = PUERTOS_BD.get(cont_p) or PUERTOS_BD.get(host_p)
                if servicio:
                    self.agregar("DOCKER_BD_PUBLICA", "critica", "confirmado",
                                 "%s del contenedor '%s' está publicado a internet (puerto %d)" % (servicio, nombre, host_p),
                                 "contenedor %s" % nombre, "%s:%d->%d" % (m.group(1), host_p, cont_p),
                                 "Docker abre el puerto directamente en el firewall del sistema: aunque ufw diga que está "
                                 "cerrado, el puerto queda abierto. Publícalo como 127.0.0.1:%d:%d o quita el 'ports'." % (host_p, cont_p),
                                 puerto=host_p)
                elif host_p in PUERTOS_PANEL or cont_p in PUERTOS_PANEL:
                    panel = PUERTOS_PANEL.get(host_p) or PUERTOS_PANEL.get(cont_p)
                    self.agregar("DOCKER_PANEL_PUBLICO", "alta" if host_p != 2375 else "critica", "revisar",
                                 "%s del contenedor '%s' está abierto a internet (puerto %d)" % (panel, nombre, host_p),
                                 "contenedor %s" % nombre, "%s:%d->%d" % (m.group(1), host_p, cont_p),
                                 "Docker se salta ufw. Si este panel debe ser público, que sea por HTTPS a través de nginx/Traefik y "
                                 "con login; si no, publícalo en 127.0.0.1 y entra por túnel SSH.", puerto=host_p)
        insp = self.s.cmd("docker_inspect", "docker inspect --format "
                          "'{{.Name}}\t{{.HostConfig.Privileged}}\t{{range .Mounts}}{{.Source}};{{end}}' "
                          "$(docker ps -q) 2>/dev/null")
        for linea in (insp or "").strip().splitlines():
            partes = linea.split("\t")
            if len(partes) < 3:
                continue
            nombre = partes[0].lstrip("/")
            imagen = next((c["imagen"] for c in self.inv["contenedores"] if c["nombre"] == nombre), "")
            gestor = GESTORES_DOCKER.search(nombre + " " + imagen)
            if partes[1].strip().lower() == "true" and not gestor:
                self.agregar("DOCKER_PRIVILEGIADO", "alta", "revisar", "El contenedor '%s' corre en modo privilegiado" % nombre,
                             "contenedor %s" % nombre, "privileged: true",
                             "Si alguien entra a ese contenedor, tiene control total del servidor.")
            if "docker.sock" in partes[2] and not gestor:
                self.agregar("DOCKER_SOCKET_MONTADO", "alta", "revisar",
                             "El contenedor '%s' tiene acceso al control de Docker (docker.sock)" % nombre,
                             "contenedor %s" % nombre, "/var/run/docker.sock",
                             "Equivale a darle acceso root al servidor. Solo herramientas de administración deberían tenerlo.")
            if re.search(r"(^|;)/(;|$)|(^|;)/etc(;|$)|(^|;)/root(;|$)", partes[2]) and not gestor:
                self.agregar("DOCKER_MONTA_SISTEMA", "alta", "revisar",
                             "El contenedor '%s' tiene montadas carpetas del sistema" % nombre, "contenedor %s" % nombre,
                             partes[2][:120], "Montar /, /etc o /root dentro de un contenedor anula el aislamiento.")

    # -------------------------------------------------------------------- ssh
    def revisar_ssh(self):
        conf = {}
        t = self.s.cmd("sshd", ["sshd", "-T"])
        if t and "permitrootlogin" in t.lower():
            for linea in t.lower().splitlines():
                p = linea.split(None, 1)
                if len(p) == 2:
                    conf.setdefault(p[0], p[1].strip())
            origen = "sshd -T"
        else:
            archivos = self.s.glob("/etc/ssh/sshd_config.d/*.conf") + ["/etc/ssh/sshd_config"]
            hubo = False
            for a in archivos:
                txt = self.s.leer(a)
                if txt is None:
                    continue
                hubo = True
                for linea in txt.splitlines():
                    linea = linea.strip()
                    if not linea or linea.startswith("#"):
                        continue
                    if linea.lower().startswith("match "):
                        break
                    p = linea.split(None, 1)
                    if len(p) == 2:
                        conf.setdefault(p[0].lower(), p[1].strip().lower())
            if not hubo:
                return
            origen = "/etc/ssh/sshd_config"
        root = conf.get("permitrootlogin", "prohibit-password")
        clave = conf.get("passwordauthentication", "yes")
        kbd = conf.get("kbdinteractiveauthentication", conf.get("challengeresponseauthentication", "no"))
        con_password = clave == "yes" or kbd == "yes"
        puerto = conf.get("port", "22")
        self.inv["sistema"]["ssh"] = "puerto %s, root: %s, contraseña: %s" % (puerto, root, "sí" if con_password else "no")
        if root == "yes" and con_password:
            self.agregar("SSH_ROOT_CON_PASSWORD", "critica", "confirmado",
                         "Se puede entrar como root con contraseña", origen,
                         "PermitRootLogin yes + PasswordAuthentication yes",
                         "Los bots prueban millones de contraseñas contra 'root' cada día. Si adivinan la tuya, tienen el "
                         "servidor completo. Usa llaves SSH y desactiva las contraseñas.")
        elif con_password:
            self.agregar("SSH_CON_PASSWORD", "alta", "confirmado", "Se puede entrar por SSH con contraseña", origen,
                         "PasswordAuthentication yes",
                         "Las contraseñas se pueden adivinar por fuerza bruta. Con llaves SSH ese ataque es imposible.")
        elif root == "yes":
            self.agregar("SSH_ROOT", "baja", "confirmado", "Se permite entrar directo como root (con llave)", origen,
                         "PermitRootLogin yes",
                         "Con llave es aceptable, pero es mejor un usuario normal con sudo y 'PermitRootLogin prohibit-password' o 'no'.")
        protegido = self.servicio_activo("fail2ban") or self.servicio_activo("crowdsec")
        if con_password and not protegido:
            self.agregar("SIN_FAIL2BAN", "media", "confirmado", "Nada bloquea a quien prueba contraseñas sin parar",
                         "servicios", "fail2ban/crowdsec no están activos",
                         "Instala fail2ban para bloquear automáticamente las IPs que fallan muchas veces.")
        fallos = self.s.cmd("ssh_fallos", "(journalctl -u ssh -u sshd --since '-24h' --no-pager -q 2>/dev/null || "
                            "cat /var/log/auth.log 2>/dev/null) | grep -cE 'Failed password|Invalid user'")
        if fallos and fallos.strip().isdigit():
            self.inv["sistema"]["intentos_ssh_fallidos_24h"] = int(fallos.strip())
        # llaves autorizadas: solo los comentarios (nunca la llave)
        for ak in ["/root/.ssh/authorized_keys"] + self.s.glob("/home/*/.ssh/authorized_keys"):
            txt = self.s.leer(ak)
            if not txt:
                continue
            for linea in txt.splitlines():
                p = linea.strip().split()
                if len(p) >= 2 and not linea.strip().startswith("#"):
                    comentario = " ".join(p[2:]) if len(p) > 2 else "(sin nombre)"
                    usuario = ak.split("/")[2] if ak.startswith("/home/") else "root"
                    self.inv["llaves_ssh_autorizadas"].append({"usuario": usuario, "llave": comentario[:60]})
        if self.inv["llaves_ssh_autorizadas"]:
            self.manuales.append("Llaves SSH con acceso a tu servidor: " + ", ".join(
                "%s (%s)" % (k["llave"], k["usuario"]) for k in self.inv["llaves_ssh_autorizadas"][:15]) +
                ". Si alguna no la reconoces (un freelancer antiguo, otra computadora), bórrala de authorized_keys.")

    def servicio_activo(self, nombre):
        if not hasattr(self, "_servicios"):
            out = self.s.cmd("servicios", ["systemctl", "list-units", "--type=service", "--state=running",
                                           "--no-legend", "--plain", "--no-pager"]) or ""
            self._servicios = {l.split()[0].replace(".service", "") for l in out.splitlines() if l.strip()}
        return any(s == nombre or s.startswith(nombre + "@") or s.startswith(nombre + "-") for s in self._servicios)

    # ---------------------------------------------------------- actualizaciones
    def revisar_actualizaciones(self):
        apt = self.s.cmd("apt_check", ["/usr/lib/update-notifier/apt-check"], combinar=True)
        seguridad = None
        if apt:
            m = re.search(r"(\d+);(\d+)", apt)
            if m:
                seguridad = int(m.group(2))
                self.inv["sistema"]["actualizaciones"] = "%s pendientes (%s de seguridad)" % (m.group(1), m.group(2))
        if seguridad is None:
            lista = self.s.cmd("apt_lista", "apt list --upgradable 2>/dev/null")
            if lista is not None:
                seguridad = sum(1 for l in lista.splitlines() if "-security" in l)
                self.inv["sistema"]["actualizaciones"] = "%d de seguridad pendientes" % seguridad
        if seguridad:
            self.agregar("PARCHES_PENDIENTES", "alta" if seguridad >= 20 else "media", "confirmado",
                         "Hay %d actualizaciones de seguridad sin instalar" % seguridad, "apt", None,
                         "Son fallas ya conocidas y publicadas. Instálalas con 'sudo apt update && sudo apt upgrade'.")
        if self.s.existe("/var/run/reboot-required") or self.s.existe("/run/reboot-required"):
            self.agregar("REINICIO_PENDIENTE", "media", "confirmado",
                         "El servidor necesita reiniciarse para aplicar parches de seguridad", "/var/run/reboot-required", None,
                         "Algunas actualizaciones (sobre todo del kernel) solo se activan al reiniciar. Hazlo en un horario de poco tráfico.")
        auto = self.s.leer("/etc/apt/apt.conf.d/20auto-upgrades") or ""
        if not re.search(r'Unattended-Upgrade\s+"1"', auto):
            if self.s.existe("/etc/apt") or self.s.simular:
                self.agregar("SIN_ACTUALIZACIONES_AUTO", "baja", "confirmado",
                             "Las actualizaciones de seguridad no se instalan solas", "/etc/apt/apt.conf.d/20auto-upgrades",
                             None, "Activa 'unattended-upgrades' para que los parches de seguridad se instalen automáticamente.")

    # ---------------------------------------------------------------- usuarios
    def revisar_usuarios(self):
        pw = self.s.leer("/etc/passwd") or ""
        for l in pw.splitlines():
            p = l.split(":")
            if len(p) > 3 and p[2] == "0" and p[0] != "root":
                self.agregar("USUARIO_UID0", "critica", "confirmado",
                             "Hay otro usuario con poderes de root: '%s'" % p[0], "/etc/passwd", p[0],
                             "Es una técnica típica de atacantes para no perder el acceso. Si no lo creaste tú, el servidor está comprometido.")
        sh = self.s.leer("/etc/shadow")
        if sh is None:
            if not self.s.es_root:
                self.omitir("contraseñas vacías (/etc/shadow necesita sudo)")
            return
        login = {p.split(":")[0] for p in pw.splitlines() if p.count(":") >= 6 and not re.search(r"nologin|false|sync$", p.split(":")[-1])}
        for l in sh.splitlines():
            p = l.split(":")
            if len(p) > 1 and p[1] == "" and p[0] in login:
                self.agregar("USUARIO_SIN_PASSWORD", "critica", "confirmado",
                             "El usuario '%s' no tiene contraseña" % p[0], "/etc/shadow", p[0],
                             "Cualquiera puede entrar con ese usuario si el servicio lo permite.")

    # ------------------------------------------------- señales de compromiso
    def revisar_compromiso(self):
        ps = self.s.cmd("ps", ["ps", "-eo", "user:20,pid,pcpu,args", "--sort=-pcpu", "--no-headers"])
        for linea in (ps or "").splitlines()[:400]:
            p = linea.split(None, 3)
            if len(p) < 4:
                continue
            usuario, pid, cpu, args = p
            sospechoso = MINEROS.search(args) or re.match(r"(/tmp/|/dev/shm/|/var/tmp/)", args)
            if sospechoso:
                self.agregar("PROCESO_SOSPECHOSO", "critica", "revisar",
                             "Proceso sospechoso corriendo (posible minero o malware)", "proceso %s (%s)" % (pid, usuario),
                             args[:120],
                             "Los mineros de criptomonedas y backdoors suelen correr desde /tmp o /dev/shm. Si no lo "
                             "reconoces, el servidor está comprometido: lee la sección de incidente en la guía.")
            try:
                if not sospechoso and float(cpu) > 85 and not re.search(r"node|python|php|java|postgres|mysql|mongod|redis|dockerd|"
                                                     r"containerd|nginx|apache|ffmpeg|chrome|clickhouse|elastic|apt|dpkg|ps\b",
                                                     args, re.I):
                    self.agregar("CPU_ALTA", "media", "revisar", "Un proceso desconocido usa %s%% de CPU" % cpu,
                                 "proceso %s (%s)" % (pid, usuario), args[:120],
                                 "Un uso de CPU muy alto y constante es la señal más común de un minero oculto.")
            except ValueError:
                pass
        # ejecutables en carpetas temporales
        for base in ("/tmp", "/var/tmp", "/dev/shm"):
            for dirpath, dirnames, filenames in self.s.caminar(base, 3, ocultos=True):
                dirnames[:] = [d for d in dirnames if not d.startswith(("systemd-private", "snap-private", ".X11", ".ICE",
                                                                         ".font-unix", ".XIM", ".Test-unix", "tmux-"))]
                for f in filenames:
                    ruta = dirpath.rstrip("/") + "/" + f
                    modo = self.s.modo(ruta)
                    if modo is None or not (modo & 0o111):
                        continue
                    if f.endswith((".sh", ".so")) or self.es_binario(ruta) or f.startswith("."):
                        self.agregar("EJECUTABLE_EN_TMP", "alta", "revisar", "Programa ejecutable escondido en una carpeta temporal",
                                     ruta, None,
                                     "Los atacantes dejan sus programas en /tmp, /var/tmp o /dev/shm. Revisa qué es antes de borrarlo.")
        # cron
        crones = ["/etc/crontab"] + self.s.glob("/etc/cron.d/*") + self.s.glob("/var/spool/cron/crontabs/*") + \
            self.s.glob("/var/spool/cron/*")
        self._cron_texto = ""
        if not self.s.glob("/var/spool/cron/crontabs/*") and not self.s.es_root:
            self.omitir("tareas programadas de otros usuarios (necesita sudo)")
        for c in crones:
            txt = self.s.leer(c)
            if not txt:
                continue
            self._cron_texto += txt + "\n"
            for i, linea in enumerate(txt.splitlines(), 1):
                if linea.strip().startswith("#"):
                    continue
                if CRON_MALO.search(linea):
                    self.agregar("CRON_SOSPECHOSO", "critica", "revisar", "Tarea programada sospechosa", "%s:%d" % (c, i),
                                 linea.strip()[:140],
                                 "Descargar y ejecutar código, o correr algo desde /tmp, es la forma típica en que un atacante "
                                 "se reinstala aunque borres su programa.")
        pre = self.s.leer("/etc/ld.so.preload")
        if pre and pre.strip():
            self.agregar("LD_PRELOAD", "critica", "revisar", "Hay una librería que se carga en todos los programas (ld.so.preload)",
                         "/etc/ld.so.preload", pre.strip()[:120],
                         "Es una técnica de rootkits para esconder procesos y archivos. Casi ningún servidor normal la usa.")
        for unidad in self.s.glob("/etc/systemd/system/*.service"):
            txt = self.s.leer(unidad) or ""
            m = re.search(r"^ExecStart\s*=\s*(.+)$", txt, re.M)
            if m and (re.search(r"^-?(/tmp/|/dev/shm/|/var/tmp/)", m.group(1)) or CRON_MALO.search(" " + m.group(1))
                      or MINEROS.search(m.group(1))):
                self.agregar("SERVICIO_SOSPECHOSO", "critica", "revisar", "Servicio del sistema sospechoso", unidad,
                             m.group(1)[:140], "Un servicio que ejecuta algo desde /tmp o descarga código al arrancar es típico de malware.")

    def es_binario(self, ruta):
        try:
            with open(self.s.ruta(ruta), "rb") as f:
                return f.read(4) == b"\x7fELF"
        except OSError:
            return False

    # --------------------------------------------------------- apps y secretos
    def revisar_apps_y_secretos(self):
        apps = []
        envs = []
        for base in DIRS_APPS:
            prof = 2 if base == "/var/lib/docker/volumes" else 4
            for dirpath, dirnames, filenames in self.s.caminar(base, prof):
                if any(m in filenames for m in MARCAS_APP):
                    if not any(dirpath.startswith(a.rstrip("/") + "/") for a in apps):
                        apps.append(dirpath)
                for f in filenames:
                    if f.startswith(".env") and not f.endswith((".example", ".sample", ".template")):
                        envs.append(dirpath.rstrip("/") + "/" + f)
        self.inv["apps_detectadas"] = apps[:30]
        for e in envs[:200]:
            modo = self.s.modo(e)
            if modo is not None and modo & 0o004:
                self.agregar("ENV_LEGIBLE", "media", "confirmado", "Cualquier usuario del servidor puede leer %s" % e, e,
                             oct(modo & 0o777),
                             "Si otro programa del servidor es hackeado (un plugin, otra app), puede leer tus llaves. "
                             "Ponle permisos 600: chmod 600 " + e)
        # nginx sirviendo carpetas con .env o .git
        textos = []
        for c in self.s.glob("/etc/nginx/sites-enabled/*") + self.s.glob("/etc/nginx/conf.d/*.conf") + ["/etc/nginx/nginx.conf"]:
            t = self.s.leer(c)
            if t:
                textos.append((c, t))
        if textos:
            protege_ocultos = any(re.search(r"location\s+~\*?\s+/\\\.(?!well)", t) and re.search(r"deny\s+all|return\s+40[34]", t)
                                  for _, t in textos)
            for c, t in textos:
                for m in re.finditer(r"^\s*root\s+([^;]+);", t, re.M):
                    raiz = m.group(1).strip().strip("\"'")
                    expuestos = [x for x in (".env", ".git") if self.s.existe(raiz.rstrip("/") + "/" + x)]
                    if expuestos and not protege_ocultos:
                        self.agregar("NGINX_SIRVE_OCULTOS", "critica", "revisar",
                                     "nginx publica una carpeta que contiene %s" % " y ".join(expuestos), c,
                                     "root %s" % raiz,
                                     "Cualquiera podría descargar %s desde tu dominio. Bloquea los archivos ocultos en nginx o "
                                     "saca la carpeta del proyecto de la carpeta pública." % "/".join(expuestos))
            if not any(re.search(r"server_tokens\s+off", t) for _, t in textos):
                self.agregar("NGINX_VERSION", "baja", "confirmado", "nginx muestra su versión", "/etc/nginx/nginx.conf",
                             None, "Agrega 'server_tokens off;' para no facilitar a los bots buscar fallas de tu versión.")

    # ------------------------------------------------------ backups y certificados
    def revisar_backups_y_certificados(self):
        timers = self.s.cmd("timers", ["systemctl", "list-timers", "--all", "--no-legend", "--plain", "--no-pager"]) or ""
        texto = getattr(self, "_cron_texto", "") + timers
        nombres_cont = " ".join(c["nombre"] + " " + c["imagen"] for c in self.inv["contenedores"])
        if not BACKUP.search(texto) and not BACKUP.search(nombres_cont):
            self.agregar("SIN_BACKUP", "media", "revisar", "No se encontró ninguna copia de seguridad automática",
                         "cron / systemd timers", None,
                         "Si te hackean, borran la base de datos o se daña el disco, no hay cómo recuperar. Puede que uses "
                         "los snapshots de tu proveedor: confírmalo en su panel.")
        hoy = datetime.datetime.utcnow()
        for cert in self.s.glob("/etc/letsencrypt/live/*/cert.pem"):
            vence = self.vencimiento_cert(cert)
            if vence is None:
                continue
            dias = (vence - hoy).days
            dominio = cert.split("/")[-2]
            if dias < 0:
                self.agregar("CERTIFICADO_VENCIDO", "alta", "confirmado", "El certificado HTTPS de %s está vencido" % dominio,
                             cert, "venció el %s" % vence.date(), "Los navegadores muestran 'sitio no seguro' y los clientes se van.")
            elif dias < 14:
                self.agregar("CERTIFICADO_POR_VENCER", "media", "confirmado",
                             "El certificado HTTPS de %s vence en %d días" % (dominio, dias), cert, str(vence.date()),
                             "Revisa que la renovación automática funcione: sudo certbot renew --dry-run")

    def vencimiento_cert(self, ruta):
        try:
            import ssl
            datos = ssl._ssl._test_decode_cert(self.s.ruta(ruta))
            return datetime.datetime.strptime(datos["notAfter"], "%b %d %H:%M:%S %Y %Z")
        except Exception:
            pass
        try:
            r = subprocess.run(["openssl", "x509", "-enddate", "-noout", "-in", self.s.ruta(ruta)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=10)
            m = re.search(r"notAfter=(.+)", r.stdout)
            return datetime.datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z") if m else None
        except Exception:
            return None

    # --------------------------------------------------------------- ejecutar
    def ejecutar(self):
        for paso in (self.revisar_sistema, self.revisar_firewall, self.revisar_puertos, self.revisar_docker,
                     self.revisar_ssh, self.revisar_actualizaciones, self.revisar_usuarios, self.revisar_compromiso,
                     self.revisar_apps_y_secretos, self.revisar_backups_y_certificados):
            try:
                paso()
            except Exception as e:  # una revisión que falla no debe tumbar las demás
                self.notas.append("La revisión '%s' falló: %s" % (paso.__name__.replace("revisar_", ""), type(e).__name__))
        if self.firewall_activo is not False:
            self.manuales.append("Firewall del proveedor: si tu VPS es de Hetzner, DigitalOcean, AWS, Oracle o similar, "
                                 "revisa en su panel que solo estén abiertos los puertos 22, 80 y 443.")
        self.manuales.append("Acceso al panel del proveedor del VPS: activa verificación en dos pasos (2FA). Quien entre "
                             "ahí puede reiniciar tu servidor en modo rescate y leer todo el disco.")
        if self.omitidas:
            self.notas.append("Sin sudo no se pudo revisar: " + "; ".join(self.omitidas) +
                              ". Vuelve a ejecutar con sudo para una revisión completa.")
        self.hallazgos.sort(key=lambda x: (SEVERIDADES.index(x["severidad"]), x["confianza"] != "confirmado"))
        resumen = {s: sum(1 for h in self.hallazgos if h["severidad"] == s) for s in SEVERIDADES}
        return {"tipo": "servidor", "con_sudo": self.s.es_root, "resumen": resumen, "hallazgos": self.hallazgos,
                "inventario": self.inv, "verificaciones_manuales": self.manuales, "notas": self.notas}


def main():
    ap = argparse.ArgumentParser(description="Escáner de seguridad del servidor (solo lectura)")
    ap.add_argument("--raiz", default="/", help="(pruebas) carpeta que simula la raíz del servidor")
    ap.add_argument("--simular", help="(pruebas) carpeta con salidas de comandos simuladas")
    args = ap.parse_args()
    resultado = EscanerServidor(Sistema(args.raiz, args.simular)).ejecutar()
    json.dump(resultado, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
