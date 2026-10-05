#!/usr/bin/env python3
"""Pruebas automáticas del escáner contra apps con vulnerabilidades plantadas.

Uso: python3 pruebas/test_escanear.py
Regenera las apps, levanta dos sitios de prueba locales y verifica:
  - que se detecta cada vulnerabilidad plantada (recall)
  - que la app bien hecha y el sitio SPA limpio no dan alarmas críticas/altas (falsos positivos)
  - que ninguna llave aparece completa en la salida
"""
import json
import os
import socket
import subprocess
import sys
import time
import unittest

AQUI = os.path.dirname(os.path.abspath(__file__))
SCRIPTS = os.path.normpath(os.path.join(AQUI, "..", "auditoria-seguridad-web", "scripts"))
ESCANER = os.path.join(SCRIPTS, "escanear.py")
APPS = os.path.join(AQUI, "apps-generadas")
sys.path.insert(0, AQUI)
from crear_apps import LLAVES_COMPLETAS  # noqa: E402


def escanear(*args):
    r = subprocess.run([sys.executable, ESCANER, *args, "--sin-red"], capture_output=True, text=True, cwd=APPS)
    assert r.returncode == 0, r.stderr
    return r.stdout, json.loads(r.stdout)


def tiene(datos, regla, archivo=None, sev=None):
    for h in datos["hallazgos"]:
        if h["regla"] == regla and (archivo is None or (h["archivo"] or "").endswith(archivo)) and \
                (sev is None or h["severidad"] == sev):
            return True
    return False


def puerto_libre():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class PruebasReporteHTML(unittest.TestCase):
    def test_escapa_html_y_enmascara_llaves(self):
        import tempfile
        datos = {"proyecto": "<script>alert(1)</script>", "rotar_hoy": [{"llave": "OpenAI", "donde": "panel"}],
                 "hallazgos": [{"severidad": "critica", "titulo": "x <img src=x onerror=alert(1)>",
                                "que_pasa": "llave " + LLAVES_COMPLETAS[0], "instrucciones_ia": "usa " + LLAVES_COMPLETAS[1]},
                               {"severidad": "baja", "titulo": "cabeceras"}]}
        with tempfile.TemporaryDirectory() as tmp:
            entrada, salida = os.path.join(tmp, "h.json"), os.path.join(tmp, "r.html")
            with open(entrada, "w", encoding="utf-8") as f:
                json.dump(datos, f)
            r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "generar_reporte.py"), entrada, salida],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(salida, encoding="utf-8") as f:
                h = f.read()
        self.assertNotIn("<script>alert", h)
        self.assertNotIn("<img src=x", h)
        for llave in LLAVES_COMPLETAS:
            self.assertNotIn(llave, h)
        self.assertIn("Haz esto hoy", h)
        self.assertIn("Prompt para arreglarlo", h)
        self.assertEqual(h.count('class="card vuln"'), 2)


class PruebasEscaner(unittest.TestCase):
    servidores = []

    @classmethod
    def setUpClass(cls):
        subprocess.run([sys.executable, os.path.join(AQUI, "crear_apps.py")], check=True, capture_output=True)
        cls.p_vuln, cls.p_spa = puerto_libre(), puerto_libre()
        for carpeta, puerto, extra in (("sitio-publicado", cls.p_vuln, []), ("sitio-spa-limpio", cls.p_spa, ["--spa"])):
            cls.servidores.append(subprocess.Popen([sys.executable, os.path.join(AQUI, "servidor_prueba.py"),
                                                    os.path.join(APPS, carpeta), str(puerto), *extra]))
        time.sleep(1)

    @classmethod
    def tearDownClass(cls):
        for s in cls.servidores:
            s.terminate()

    def sin_llaves_completas(self, texto):
        for llave in LLAVES_COMPLETAS:
            self.assertNotIn(llave, texto, "la salida muestra una llave completa sin enmascarar")

    def test_tienda_nextjs_supabase(self):
        texto, d = escanear("tienda-nextjs-supabase")
        esperados = [
            ("ENV_EN_REPOSITORIO", ".env.local"),
            ("SECRETO_EN_VARIABLE_PUBLICA", ".env.local"),
            ("SECRETO_EN_VARIABLE_PUBLICA", "AsistenteIA.tsx"),
            ("SECRETO_EN_FRONTEND", "lib/supabaseClient.ts"),  # service_role importada por una página 'use client'
            ("SUPABASE_SIN_RLS", "init.sql"),
            ("SUPABASE_POLITICA_ABIERTA", "init.sql"),
            ("ADMIN_SIN_PROTECCION", "app/admin/page.tsx"),
            ("PRECIO_DESDE_CLIENTE", "checkout/route.ts"),
            ("WEBHOOK_SIN_FIRMA", "webhooks/stripe/route.ts"),
            ("DEPENDENCIA_VULNERABLE", "package.json"),
        ]
        for regla, archivo in esperados:
            self.assertTrue(tiene(d, regla, archivo), "no detectó %s en %s" % (regla, archivo))
        sin_rls = [h["evidencia"] for h in d["hallazgos"] if h["regla"] == "SUPABASE_SIN_RLS"]
        self.assertEqual(sin_rls, ["orders"], "solo 'orders' no tiene RLS")
        self.sin_llaves_completas(texto)

    def test_firebase_chatbot(self):
        texto, d = escanear("app-firebase-chatbot")
        esperados = [
            ("FIREBASE_REGLAS_ABIERTAS", "firestore.rules"),
            ("FIREBASE_MODO_PRUEBA", "storage.rules"),
            ("SECRETO_EN_VARIABLE_PUBLICA", "src/chat.js"),
            ("LLM_LLAVE_EN_NAVEGADOR", "src/chat.js"),
            ("LLM_HERRAMIENTAS_PELIGROSAS", "server/agente.js"),
            ("LLM_PROMPT_INYECCION", "server/agente.js"),
            ("LLM_SIN_LIMITES", "server/index.js"),
            ("ADMIN_SIN_PROTECCION", "server/index.js"),
            ("SECRETO_EN_CODIGO", "server/pagos.js"),
            ("CORS_ABIERTO", "server/index.js"),
        ]
        for regla, archivo in esperados:
            self.assertTrue(tiene(d, regla, archivo), "no detectó %s en %s" % (regla, archivo))
        # la apiKey web de Firebase es pública por diseño: no debe salir como secreto
        self.assertFalse(any("firebase.js" in (h["archivo"] or "") for h in d["hallazgos"]),
                         "marcó la apiKey pública de Firebase como secreto")
        self.assertFalse(tiene(d, "ENV_EN_REPOSITORIO"), ".env está en .gitignore")
        self.sin_llaves_completas(texto)

    def test_shopify(self):
        texto, d = escanear("app-shopify")
        self.assertTrue(tiene(d, "SECRETO_EN_FRONTEND", "theme/assets/custom.js", "critica"))
        self.assertTrue(tiene(d, "SECRETO_EN_CODIGO", "web/shopify.js"))
        self.assertTrue(tiene(d, "WEBHOOK_SIN_FIRMA", "web/webhooks.js"))
        self.assertTrue(tiene(d, "OPERACION_SENSIBLE_SIN_AUTH", "web/index.js"))
        self.assertFalse(tiene(d, "WEBHOOK_SIN_FIRMA", "web/index.js"), "index.js solo monta el router")
        self.assertFalse(any((h["archivo"] or "").endswith(".env") for h in d["hallazgos"]), ".env está ignorado")
        self.sin_llaves_completas(texto)

    def test_app_segura_sin_falsas_alarmas(self):
        _, d = escanear("tienda-segura")
        graves = [h for h in d["hallazgos"] if h["severidad"] in ("critica", "alta", "media")]
        self.assertEqual(graves, [], "falsas alarmas en la app segura: %s" % graves)

    def test_sitio_publicado_vulnerable(self):
        texto, d = escanear("no-existe", "--url", "http://localhost:%d" % self.p_vuln)
        self.assertTrue(tiene(d, "ARCHIVO_EXPUESTO", "/.env", "critica"))
        self.assertTrue(tiene(d, "ARCHIVO_EXPUESTO", "/.git/HEAD"))
        secretos = [h for h in d["hallazgos"] if h["regla"] == "SECRETO_EN_SITIO_PUBLICADO"]
        self.assertGreaterEqual(len(secretos), 2, "debe encontrar la llave de OpenAI y la service_role en el JS")
        self.assertTrue(tiene(d, "SOURCEMAPS_PUBLICOS"))
        self.assertTrue(tiene(d, "CABECERAS_FALTANTES"))
        self.sin_llaves_completas(texto)

    def test_sitio_spa_sin_falsos_positivos(self):
        # devuelve index.html con 200 para /.env, /.git/HEAD, etc.: no debe reportarlos
        _, d = escanear("no-existe", "--url", "http://localhost:%d" % self.p_spa)
        graves = [h for h in d["hallazgos"] if h["severidad"] in ("critica", "alta", "media")]
        self.assertEqual(graves, [], "falsos positivos en el sitio SPA: %s" % graves)
        self.assertTrue(any("anon key" in m for m in d["verificaciones_manuales"]))


class PruebasServidor(unittest.TestCase):
    """Modo VPS: servidores simulados (carpetas con /etc, /tmp... y salidas de comandos)."""

    @classmethod
    def setUpClass(cls):
        import shutil
        import tempfile
        cls.tmp = tempfile.mkdtemp(prefix="servidores-")  # disco del sistema: respeta permisos de archivos
        subprocess.run([sys.executable, os.path.join(AQUI, "crear_servidores.py"), cls.tmp], check=True, capture_output=True)
        subprocess.run([sys.executable, os.path.join(AQUI, "crear_apps.py")], check=True, capture_output=True)
        # el VPS vulnerable aloja la tienda vulnerable
        shutil.copytree(os.path.join(APPS, "tienda-nextjs-supabase"),
                        os.path.join(cls.tmp, "servidor-vulnerable", "var", "www", "tienda"), dirs_exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        import shutil
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def escanear_servidor(self, nombre):
        raiz = os.path.join(self.tmp, nombre)
        r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "escanear_servidor.py"), "--raiz", raiz,
                            "--simular", os.path.join(raiz, "_comandos")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_servidor_vulnerable(self):
        d = self.escanear_servidor("servidor-vulnerable")
        reglas = [h["regla"] for h in d["hallazgos"]]
        for regla in ["DOCKER_BD_PUBLICA", "BD_EXPUESTA", "DOCKER_PANEL_PUBLICO", "SSH_ROOT_CON_PASSWORD", "SIN_FAIL2BAN",
                      "FIREWALL_INACTIVO", "USUARIO_UID0", "USUARIO_SIN_PASSWORD", "PROCESO_SOSPECHOSO", "CRON_SOSPECHOSO",
                      "LD_PRELOAD", "SERVICIO_SOSPECHOSO", "EJECUTABLE_EN_TMP", "NGINX_SIRVE_OCULTOS", "ENV_LEGIBLE",
                      "PARCHES_PENDIENTES", "REINICIO_PENDIENTE", "SIN_ACTUALIZACIONES_AUTO", "DISCO_LLENO",
                      "CERTIFICADO_POR_VENCER", "SIN_BACKUP", "DOCKER_SOCKET_MONTADO", "NGINX_VERSION"]:
            self.assertIn(regla, reglas, "no detectó %s" % regla)
        self.assertEqual(reglas.count("DOCKER_BD_PUBLICA"), 1, "Redis en IPv4 e IPv6 es un solo problema")
        self.assertNotIn("CPU_ALTA", reglas, "el minero ya está reportado como proceso sospechoso")
        # Portainer necesita docker.sock y modo privilegiado: no es falsa alarma
        self.assertFalse(any("portainer" in (h["archivo"] or "") and h["regla"] in ("DOCKER_SOCKET_MONTADO", "DOCKER_PRIVILEGIADO")
                             for h in d["hallazgos"]))
        self.assertEqual(d["inventario"]["sistema"]["intentos_ssh_fallidos_24h"], 18342)
        self.assertEqual(len(d["inventario"]["llaves_ssh_autorizadas"]), 2)
        self.assertNotIn("AAAAC3", json.dumps(d), "nunca debe mostrar el contenido de una llave SSH")
        self.assertIn("/var/www/tienda", d["inventario"]["apps_detectadas"])

    def test_servidor_seguro_sin_falsas_alarmas(self):
        d = self.escanear_servidor("servidor-seguro")
        graves = [h for h in d["hallazgos"] if h["severidad"] in ("critica", "alta", "media")]
        self.assertEqual(graves, [], "falsas alarmas en el servidor seguro: %s" % graves)
        self.assertEqual(d["notas"], [])

    def test_auditar_vps_flujo_completo(self):
        import glob as g
        import socket
        antes = set(g.glob("/tmp/auditoria-seguridad-*"))
        control = socket.socket()
        control.bind(("127.0.0.1", 0))
        control.listen(5)
        try:
            raiz = os.path.join(self.tmp, "servidor-vulnerable")
            r = subprocess.run([sys.executable, os.path.join(SCRIPTS, "auditar_vps.py"), "alumno@127.0.0.1", "--local",
                                "--args-servidor", "--raiz %s --simular %s" % (raiz, os.path.join(raiz, "_comandos")),
                                "--raiz-apps", raiz, "--puerto-control", str(control.getsockname()[1])],
                               capture_output=True, text=True, timeout=180)
        finally:
            control.close()
        self.assertEqual(r.returncode, 0, r.stdout[-500:] + r.stderr[-500:])
        d = json.loads(r.stdout)
        self.assertTrue(d["servidor"]["hallazgos"])
        tienda = [a for a in d["apps"] if a["ruta"] == "/var/www/tienda"]
        self.assertTrue(tienda and tienda[0]["resultado"]["resumen"]["critica"] > 0, "debe revisar el código de la app")
        self.assertTrue(all(h.get("grupo") == "codigo" for h in tienda[0]["resultado"]["hallazgos"]))
        self.assertIn("5432", d["puertos_desde_internet"], "debe probar los puertos desde fuera")
        self.assertEqual(set(g.glob("/tmp/auditoria-seguridad-*")), antes, "debe borrar la carpeta temporal")

    def test_ajuste_por_sondeo(self):
        sys.path.insert(0, SCRIPTS)
        from auditar_vps import ajustar_por_sondeo
        hs = [{"regla": "BD_ESCUCHA_PUBLICA", "severidad": "baja", "confianza": "revisar", "puerto": 5432,
               "titulo": "PostgreSQL escucha en todas las interfaces, pero el firewall lo bloquea (puerto 5432)", "detalle": ""},
              {"regla": "DOCKER_BD_PUBLICA", "severidad": "critica", "confianza": "confirmado", "puerto": 6379,
               "titulo": "Redis publicado", "detalle": ""}]
        ajustar_por_sondeo(hs, {5432: True, 6379: False})
        self.assertEqual(hs[0]["severidad"], "critica", "si responde desde internet, es crítico")
        self.assertEqual(hs[1]["severidad"], "media", "si no responde, baja a medio pero no desaparece")
        self.assertEqual(hs[1]["confianza"], "revisar")

    def test_reporte_con_servidor(self):
        import tempfile
        datos = {"proyecto": "tienda", "conexion": "ssh deploy@203.0.113.10",
                 "servidor_info": {"Sistema": "Ubuntu 22.04", "Intentos de entrar por SSH (24 h)": "18.342"},
                 "hallazgos": [{"severidad": "critica", "grupo": "servidor", "titulo": "Se puede entrar como root con contraseña"},
                               {"severidad": "alta", "grupo": "codigo", "titulo": "Precio desde el navegador"}]}
        with tempfile.TemporaryDirectory() as tmp:
            entrada, salida = os.path.join(tmp, "h.json"), os.path.join(tmp, "r.html")
            with open(entrada, "w", encoding="utf-8") as f:
                json.dump(datos, f)
            subprocess.run([sys.executable, os.path.join(SCRIPTS, "generar_reporte.py"), entrada, salida], check=True,
                           capture_output=True)
            with open(salida, encoding="utf-8") as f:
                h = f.read()
        self.assertIn("Tu servidor", h)
        self.assertIn("Tu código", h)
        self.assertIn("18.342", h)
        self.assertIn("ssh deploy@203.0.113.10", h)
        self.assertIn("NO cierres la sesión actual", h)


if __name__ == "__main__":
    unittest.main(verbosity=2)
