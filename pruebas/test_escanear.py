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


if __name__ == "__main__":
    unittest.main(verbosity=2)
