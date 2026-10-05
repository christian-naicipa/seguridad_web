#!/usr/bin/env python3
"""Sirve una carpeta como si fuera un sitio publicado.

Uso: python3 servidor_prueba.py CARPETA PUERTO [--spa]
--spa: devuelve index.html (con 200) para cualquier ruta que no exista, como hacen
       Vercel/Netlify con apps React. Sirve para probar que el escáner no da falsas alarmas.
"""
import functools
import http.server
import os
import sys


class Manejador(http.server.SimpleHTTPRequestHandler):
    spa = False

    def end_headers(self):
        self.send_header("X-Powered-By", "Express")
        super().end_headers()

    def send_head(self):
        ruta = self.translate_path(self.path)
        if self.spa and not os.path.exists(ruta):
            self.path = "/index.html"
        return super().send_head()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    carpeta, puerto = sys.argv[1], int(sys.argv[2])
    Manejador.spa = "--spa" in sys.argv
    handler = functools.partial(Manejador, directory=carpeta)
    http.server.ThreadingHTTPServer(("127.0.0.1", puerto), handler).serve_forever()
