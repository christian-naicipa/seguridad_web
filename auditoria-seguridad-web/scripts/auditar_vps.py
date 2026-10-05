#!/usr/bin/env python3
"""Audita un VPS por SSH desde tu computadora. Solo lee: no cambia nada en el servidor.

Uso:
    python3 auditar_vps.py usuario@IP [-p 22] [-i ~/.ssh/mi_llave] [--app /var/www/mi-tienda ...]

Qué hace:
  1. Se conecta por SSH (con llave; si tu VPS solo acepta contraseña, mira la ayuda al final).
  2. Sube escanear_servidor.py y escanear.py a una carpeta temporal del VPS.
  3. Revisa el servidor (con sudo si está disponible sin pedir contraseña) y el código de cada app
     (las que indiques con --app o las que encuentre solo, máximo 5).
  4. Desde TU computadora prueba si los puertos delicados se pueden alcanzar desde internet.
  5. Borra la carpeta temporal del VPS y entrega un JSON con todo.
"""
import argparse
import json
import os
import shlex
import socket
import subprocess
import sys
import tempfile

AQUI = os.path.dirname(os.path.abspath(__file__))
REGLAS_PUERTO = {"BD_EXPUESTA", "PANEL_EXPUESTO", "DOCKER_BD_PUBLICA", "DOCKER_PANEL_PUBLICO", "BD_ESCUCHA_PUBLICA",
                 "PANEL_ESCUCHA_PUBLICA", "DOCKER_API_EXPUESTA"}
MAX_APPS = 5


class Conexion:
    def __init__(self, destino, puerto=None, llave=None, local=False):
        self.destino = destino
        self.local = local
        self.base = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "StrictHostKeyChecking=accept-new",
                     "-o", "ServerAliveInterval=15"]
        if os.name != "nt":
            ctl = os.path.join(tempfile.gettempdir(), "auditoria-ssh-%C")
            self.base += ["-o", "ControlMaster=auto", "-o", "ControlPath=" + ctl, "-o", "ControlPersist=60"]
        if puerto:
            self.base += ["-p", str(puerto)]
        if llave:
            self.base += ["-i", os.path.expanduser(llave)]

    def run(self, comando, entrada=None, timeout=300):
        args = ["sh", "-c", comando] if self.local else self.base + [self.destino, comando]
        r = subprocess.run(args, input=entrada, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr

    def cerrar(self):
        if not self.local and os.name != "nt":
            subprocess.run(self.base + ["-O", "exit", self.destino], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)


def sondear(host, puertos, timeout=3.0):
    """Prueba desde esta computadora si cada puerto acepta conexiones."""
    res = {}
    for p in sorted(set(puertos)):
        try:
            with socket.create_connection((host, p), timeout=timeout):
                res[p] = True
        except OSError:
            res[p] = False
    return res


def ajustar_por_sondeo(hallazgos, sondeo):
    """Corrige la gravedad de los hallazgos de puertos según lo que se ve desde internet."""
    for h in hallazgos:
        p = h.get("puerto")
        if h.get("regla") not in REGLAS_PUERTO or p not in sondeo:
            continue
        es_bd = h["regla"] in ("BD_EXPUESTA", "DOCKER_BD_PUBLICA", "BD_ESCUCHA_PUBLICA")
        if sondeo[p]:
            h["confianza"] = "confirmado"
            h["desde_internet"] = "abierto"
            if h["severidad"] in ("baja", "media"):
                h["severidad"] = "critica" if es_bd else "alta"
                h["titulo"] = h["titulo"].split(", pero")[0].replace("escucha en todas las interfaces",
                                                                      "está abierto a internet")
            h["detalle"] = "Comprobado: el puerto %d responde desde internet. " % p + h.get("detalle", "")
        else:
            h["desde_internet"] = "cerrado"
            if h["severidad"] in ("critica", "alta") and h["regla"] != "DOCKER_API_EXPUESTA":
                # No se baja a "baja": la red del alumno podría estar bloqueando ese puerto de salida.
                h["severidad"] = "media"
                h["confianza"] = "revisar"
                h["titulo"] += " (desde fuera no respondió)"
                h["detalle"] = ("Desde tu conexión el puerto %d no respondió: probablemente lo bloquea el firewall de tu "
                                "proveedor (confírmalo en su panel). Dentro del servidor sigue abierto: si ese firewall "
                                "cambia, queda expuesto. Mejor que escuche solo en 127.0.0.1." % p)
    return hallazgos


def main():
    ap = argparse.ArgumentParser(description="Auditoría de seguridad de un VPS por SSH (solo lectura)")
    ap.add_argument("destino", help="usuario@IP del VPS (o un alias de ~/.ssh/config)")
    ap.add_argument("-p", "--puerto", help="puerto SSH (por defecto 22)")
    ap.add_argument("-i", "--llave", help="archivo de llave SSH")
    ap.add_argument("--app", action="append", default=[], help="carpeta de una app en el VPS (se puede repetir)")
    ap.add_argument("--incluir-sin-uso", action="store_true",
                    help="revisar también carpetas de apps que nada usa (por defecto se omiten)")
    ap.add_argument("--sin-sondeo", action="store_true", help="no probar los puertos desde esta computadora")
    ap.add_argument("--local", action="store_true", help=argparse.SUPPRESS)  # pruebas: ejecuta 'remoto' en local
    ap.add_argument("--args-servidor", default="", help=argparse.SUPPRESS)  # pruebas: --raiz/--simular
    ap.add_argument("--puerto-control", help=argparse.SUPPRESS)  # pruebas
    ap.add_argument("--raiz-apps", default="", help=argparse.SUPPRESS)  # pruebas: prefijo de rutas de apps
    ap.add_argument("--host-sondeo", help="IP a usar para probar los puertos (si 'destino' es un alias de ~/.ssh/config)")
    args = ap.parse_args()

    con = Conexion(args.destino, args.puerto, args.llave, args.local)
    salida = {"destino": args.destino, "servidor": None, "apps": [], "apps_sin_uso": [], "puertos_desde_internet": {},
              "notas": []}
    tmp = None
    try:
        code, out, err = con.run("echo conectado && id -u && command -v python3 || echo SIN_PYTHON", timeout=40)
        if code != 0 or "conectado" not in out:
            salida["error"] = "no_se_pudo_conectar"
            salida["detalle"] = err.strip()[-400:]
            salida["ayuda"] = ("Revisa usuario, IP y puerto. Este script necesita entrar con llave SSH (sin escribir "
                               "contraseña). Si hoy entras con contraseña, ejecuta tú en la terminal: "
                               "ssh-copy-id %s  (te pedirá la contraseña una vez) y vuelve a intentarlo. "
                               "Alternativa: instala el skill en el VPS y ejecútalo ahí." % args.destino)
            return salida
        lineas = out.split()
        es_root = len(lineas) > 1 and lineas[1] == "0"
        if "SIN_PYTHON" in out:
            salida["error"] = "sin_python"
            salida["ayuda"] = "El VPS no tiene python3. Instálalo con: sudo apt install -y python3"
            return salida
        sudo = ""
        if not es_root:
            c, _, _ = con.run("sudo -n true", timeout=20)
            if c == 0:
                sudo = "sudo -n "
            else:
                salida["notas"].append(
                    "El usuario no tiene sudo sin contraseña, así que algunas revisiones se omitieron. Para una revisión "
                    "completa, entra al VPS y ejecuta el escáner con sudo (ver la guía del skill).")
        code, out, err = con.run("mktemp -d /tmp/auditoria-seguridad-XXXXXX", timeout=30)
        tmp = out.strip()
        if code != 0 or not tmp.startswith("/tmp/auditoria-seguridad-"):
            salida["error"] = "no_se_pudo_crear_temporal"
            salida["detalle"] = err.strip()[-300:]
            return salida
        for nombre in ("escanear_servidor.py", "escanear.py"):
            with open(os.path.join(AQUI, nombre), encoding="utf-8") as f:
                c, _, e = con.run("cat > %s/%s" % (shlex.quote(tmp), nombre), entrada=f.read(), timeout=60)
            if c != 0:
                salida["error"] = "no_se_pudo_subir"
                salida["detalle"] = e.strip()[-300:]
                return salida

        code, out, err = con.run("%spython3 %s/escanear_servidor.py %s" % (sudo, shlex.quote(tmp), args.args_servidor))
        try:
            servidor = json.loads(out)
        except ValueError:
            salida["error"] = "fallo_escaner_servidor"
            salida["detalle"] = (err or out).strip()[-500:]
            return salida
        salida["servidor"] = servidor

        if args.app:
            apps = args.app
        else:
            detalle = servidor["inventario"].get("apps") or [{"ruta": r, "en_uso": None}
                                                             for r in servidor["inventario"].get("apps_detectadas", [])]
            # Solo lo que está en producción: copias viejas que nada usa dan diagnósticos falsos.
            apps = [a["ruta"] for a in detalle if a["en_uso"] is True]
            if not apps:
                apps = [a["ruta"] for a in detalle if a["en_uso"] is not False]
            if args.incluir_sin_uso:
                apps += [a["ruta"] for a in detalle if a["en_uso"] is False]
            salida["apps_sin_uso"] = [a["ruta"] for a in detalle if a["en_uso"] is False]
        if len(apps) > MAX_APPS:
            salida["notas"].append("Se encontraron %d apps; se revisaron las primeras %d. Usa --app para elegir." %
                                   (len(apps), MAX_APPS))
        for app in apps[:MAX_APPS]:
            code, out, err = con.run("%spython3 %s/escanear.py %s --sin-red" % (sudo, shlex.quote(tmp),
                                                                              shlex.quote(args.raiz_apps + app)))
            try:
                resultado = json.loads(out)
                if resultado.get("archivos_revisados", 0) == 0:
                    salida["notas"].append("La carpeta %s no tiene archivos que revisar (o no existe)." % app)
                for h in resultado.get("hallazgos", []):
                    h["grupo"] = "codigo"
                    h["app"] = app
                salida["apps"].append({"ruta": app, "resultado": resultado})
            except ValueError:
                salida["notas"].append("No se pudo revisar %s: %s" % (app, (err or out).strip()[-200:]))

        if not args.sin_sondeo:
            host = args.host_sondeo or args.destino.split("@")[-1]
            puertos = [h["puerto"] for h in servidor["hallazgos"] if h.get("puerto") and h["regla"] in REGLAS_PUERTO]
            if puertos:
                try:
                    host_ip = socket.gethostbyname(host)
                except OSError:
                    host_ip = None
                control = int(args.puerto_control or args.puerto or 22)
                if host_ip and sondear(host_ip, [control]).get(control):
                    sondeo = sondear(host_ip, puertos)
                    salida["puertos_desde_internet"] = {str(k): ("abierto" if v else "cerrado") for k, v in sondeo.items()}
                    ajustar_por_sondeo(servidor["hallazgos"], sondeo)
                elif host_ip:
                    salida["notas"].append("No se pudo comprobar desde fuera qué puertos responden (ni el puerto de control "
                                           "%d respondió desde esta conexión). Los hallazgos de puertos quedan como 'revisar'." % control)
                else:
                    salida["notas"].append("No se pudo resolver %s para probar los puertos desde internet "
                                           "(si usas un alias de ~/.ssh/config, pasa la IP con --host-sondeo)." % host)
        return salida
    finally:
        if tmp and tmp.startswith("/tmp/auditoria-seguridad-"):
            con.run("rm -rf %s" % shlex.quote(tmp), timeout=30)
        con.cerrar()


if __name__ == "__main__":
    resultado = main()
    json.dump(resultado, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    sys.exit(1 if resultado.get("error") else 0)
