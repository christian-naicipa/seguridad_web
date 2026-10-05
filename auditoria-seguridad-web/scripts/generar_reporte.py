#!/usr/bin/env python3
"""Genera el reporte de seguridad en HTML (un solo archivo, sin internet).

Uso:
    python3 generar_reporte.py hallazgos-finales.json SEGURIDAD-REPORTE.html

El JSON lo escribe Claude DESPUÉS de confirmar los hallazgos del escáner. Formato:
{
  "proyecto": "mi-tienda",
  "fecha": "2026-10-05",
  "revisado": ["Código del proyecto", "Sitio publicado: https://mitienda.com"],
  "veredicto": "No la publiques todavía",            # opcional: se calcula si falta
  "resumen": "2-3 frases en lenguaje simple",
  "rotar_hoy": [{"llave": "OpenAI", "donde": "platform.openai.com → API keys"}],
  "hallazgos": [{
      "severidad": "critica|alta|media|baja",
      "titulo": "Cualquiera puede entrar a tu panel de administración",
      "donde": "app/admin/page.tsx",
      "que_pasa": "...", "riesgo": "...",
      "pasos": ["paso 1", "paso 2"],
      "instrucciones_ia": "Qué debe cambiar el agente, en concreto"
  }],
  "bien": ["..."], "manual": ["..."], "limites": ["..."]
}

Todo el texto se escapa (puede venir de código del proyecto) y cualquier llave
secreta que se haya colado se enmascara antes de escribir el HTML.
"""
import datetime
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from escanear import PATRONES_SECRETOS, decodificar_jwt, enmascarar  # noqa: E402

SEV = {
    "critica": ("Crítico", "crit"),
    "alta": ("Alto", "alto"),
    "media": ("Medio", "medio"),
    "baja": ("Bajo", "bajo"),
}
ORDEN = ["critica", "alta", "media", "baja"]


def limpiar_secretos(texto):
    """Enmascara llaves secretas que se hayan colado en el texto."""
    if not isinstance(texto, str):
        return texto
    for pid, rx, _ in PATRONES_SECRETOS:
        if pid == "google_ai":
            continue

        def reemplazo(m):
            valor = m.group(0)
            if pid == "jwt" and (decodificar_jwt(valor) or {}).get("role") != "service_role":
                return valor
            return enmascarar(valor)
        texto = rx.sub(reemplazo, texto)
    return texto


def limpiar(obj):
    if isinstance(obj, dict):
        return {k: limpiar(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [limpiar(v) for v in obj]
    return limpiar_secretos(obj)


def e(t):
    return html.escape(str(t or ""), quote=True)


def construir_prompt(h, proyecto, conexion=None):
    servidor = h.get("grupo") == "servidor"
    if servidor:
        inicio = "Arregla este problema de seguridad en mi servidor (VPS)%s." % (
            ". Me conecto con: %s" % conexion if conexion else "")
    else:
        inicio = "Arregla este problema de seguridad en mi proyecto%s." % (" \"%s\"" % proyecto if proyecto else "")
    lineas = [inicio, "", "PROBLEMA: %s" % h.get("titulo", "")]
    if h.get("donde"):
        lineas.append("DÓNDE: %s" % h["donde"])
    if h.get("que_pasa"):
        lineas.append("QUÉ PASA: %s" % h["que_pasa"])
    lineas += ["", "QUÉ HAY QUE HACER:", h.get("instrucciones_ia") or "\n".join("- " + p for p in h.get("pasos", []))]
    if servidor:
        lineas += [
            "",
            "REGLAS:",
            "- Primero revisa el estado actual (solo lectura) y explícame qué vas a cambiar antes de hacerlo.",
            "- Antes de editar un archivo de configuración, haz una copia de respaldo (.bak).",
            "- Si tocas SSH o el firewall: NO cierres la sesión actual. Comprueba que puedo entrar en una segunda "
            "conexión antes de terminar, para no quedarme fuera de mi servidor.",
            "- Cambia solo lo necesario para este problema y no reinicies servicios sin avisarme.",
            "- Al terminar, explícame en palabras simples qué cambiaste y cómo compruebo que quedó arreglado.",
        ]
        return "\n".join(lineas)
    lineas += [
        "",
        "REGLAS:",
        "- Lee primero los archivos involucrados y respeta cómo está hecho el proyecto.",
        "- No escribas llaves ni contraseñas en el código: usa variables de entorno y dime cuáles debo configurar.",
        "- Cambia solo lo necesario para este problema.",
        "- Al terminar, explícame en palabras simples qué cambiaste y cómo compruebo que quedó arreglado.",
    ]
    return "\n".join(lineas)


def veredicto_auto(conteo):
    if conteo["critica"]:
        return ("No la publiques todavía", "crit")
    if conteo["alta"]:
        return ("Arregla lo importante antes de lanzar", "alto")
    if conteo["media"]:
        return ("Bien encaminada, con detalles por mejorar", "medio")
    return ("Lista para lanzar en lo revisado", "ok")


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--txt:#1d2433;--sub:#5b6476;--line:#e4e7ec;--code:#f2f4f7;
--crit:#d92d20;--crit-bg:#fef3f2;--alto:#e8590c;--alto-bg:#fff4ed;--medio:#b54708;--medio-bg:#fffaeb;
--bajo:#1570ef;--bajo-bg:#eff8ff;--ok:#079455;--ok-bg:#ecfdf3;--radius:14px}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--card:#171b24;--txt:#e6e9ef;--sub:#98a2b3;--line:#262c38;
--code:#1f2430;--crit:#f97066;--crit-bg:#2a1414;--alto:#fd853a;--alto-bg:#2a1a10;--medio:#fdb022;--medio-bg:#2a2210;
--bajo:#53b1fd;--bajo-bg:#102033;--ok:#32d583;--ok-bg:#0f2a1d}}
*{box-sizing:border-box}html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--txt);font:16px/1.6 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:860px;margin:0 auto;padding:40px 20px 64px}
header .marca{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--sub);font-weight:600}
h1{font-size:30px;line-height:1.2;margin:6px 0 4px}
.meta{color:var(--sub);font-size:14px}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:24px;margin-top:20px}
.veredicto{display:flex;gap:16px;align-items:flex-start}
.punto{flex:0 0 14px;height:14px;border-radius:50%;margin-top:9px}
.veredicto h2{margin:0;font-size:22px}
.veredicto p{margin:6px 0 0;color:var(--sub)}
.barra{display:flex;height:12px;border-radius:99px;overflow:hidden;background:var(--line);margin:22px 0 16px}
.barra span{display:block;height:100%}
.conteos{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.conteo{border-radius:10px;padding:12px 14px;background:var(--code)}
.conteo b{display:block;font-size:26px;line-height:1.1}
.conteo small{color:var(--sub);font-size:13px}
.hoy{border-color:var(--crit);background:var(--crit-bg)}
.hoy h2{margin:0 0 4px;font-size:18px;color:var(--crit)}
.hoy p{margin:0 0 12px;color:var(--sub);font-size:14px}
.hoy ul{margin:0;padding-left:20px}.hoy li{margin:4px 0}
.seccion{display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin:40px 0 4px}
.seccion h2{margin:0;font-size:20px}
.filtros{display:flex;gap:6px;flex-wrap:wrap}
.filtros button{font:inherit;font-size:13px;border:1px solid var(--line);background:var(--card);color:var(--sub);
border-radius:99px;padding:4px 12px;cursor:pointer}
.filtros button[aria-pressed=true]{background:var(--txt);color:var(--bg);border-color:var(--txt)}
.vuln{border-left:5px solid var(--c);padding:22px 24px}
.cabeza{display:flex;gap:12px;align-items:flex-start;justify-content:space-between}
.vuln h3{margin:0;font-size:18px;line-height:1.35}
.pill{flex:0 0 auto;font-size:12px;font-weight:700;letter-spacing:.03em;padding:3px 10px;border-radius:99px;
color:var(--c);background:var(--cbg)}
.donde{display:inline-block;margin-top:8px;font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
background:var(--code);padding:3px 8px;border-radius:6px;color:var(--sub);word-break:break-all}
.dos{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:16px}
.dos h4{margin:0 0 4px;font-size:12px;letter-spacing:.06em;text-transform:uppercase;color:var(--sub)}
.dos p{margin:0}
details{margin-top:16px;border-top:1px solid var(--line);padding-top:12px}
summary{cursor:pointer;font-weight:600;font-size:15px}
summary::marker{color:var(--sub)}
ol{margin:10px 0 0;padding-left:22px}ol li{margin:4px 0}
.prompt{margin-top:16px;border:1px solid var(--line);border-radius:10px;overflow:hidden}
.prompt-top{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 12px;
background:var(--code);font-size:13px;color:var(--sub)}
.prompt-top b{color:var(--txt);font-weight:600}
.copiar{font:inherit;font-size:13px;font-weight:600;border:0;border-radius:8px;padding:6px 12px;cursor:pointer;
background:var(--txt);color:var(--bg)}
.prompt pre{margin:0;padding:14px;white-space:pre-wrap;word-break:break-word;max-height:132px;overflow:auto;
font:13px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--card)}
.lista{list-style:none;margin:0;padding:0}
.lista li{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--line)}
.lista li:last-child{border-bottom:0}
.ic{flex:0 0 22px;height:22px;border-radius:50%;display:grid;place-items:center;font-size:13px;font-weight:700;margin-top:1px}
.ic.ok{background:var(--ok-bg);color:var(--ok)}
.check label{display:flex;gap:10px;cursor:pointer}
.check input{width:18px;height:18px;margin-top:3px;accent-color:var(--ok);flex:0 0 auto}
.check input:checked+span{text-decoration:line-through;color:var(--sub)}
.limites{font-size:14px;color:var(--sub)}
.etq{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--sub);
border:1px solid var(--line);border-radius:6px;padding:1px 6px;margin-left:8px;vertical-align:2px}
.info{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:10px}
.info div{background:var(--code);border-radius:10px;padding:10px 14px}
.info small{display:block;color:var(--sub);font-size:12px}
.info b{font-size:15px;font-weight:600;word-break:break-word}
.grupo{margin:28px 0 0;font-size:14px;letter-spacing:.06em;text-transform:uppercase;color:var(--sub)}
.vacio{text-align:center;color:var(--sub);padding:28px}
footer{margin-top:40px;font-size:13px;color:var(--sub);text-align:center}
@media (max-width:640px){.wrap{padding:24px 16px 48px}h1{font-size:24px}.conteos{grid-template-columns:repeat(2,1fr)}
.dos{grid-template-columns:1fr}.card,.vuln{padding:18px}}
@media print{body{background:#fff}.filtros,.copiar{display:none}details{display:block}.prompt pre{max-height:none}
.card{break-inside:avoid}}
"""

JS = """
document.querySelectorAll('.copiar').forEach(function(b){b.addEventListener('click',function(){
var t=document.getElementById(b.dataset.for).textContent,ok=function(){var o=b.textContent;b.textContent='¡Copiado!';
setTimeout(function(){b.textContent=o},1600)};
if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(t).then(ok)}else{
var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();
try{document.execCommand('copy');ok()}catch(e){}document.body.removeChild(a)}})});
var fs=document.querySelectorAll('.filtros button');fs.forEach(function(b){b.addEventListener('click',function(){
fs.forEach(function(x){x.setAttribute('aria-pressed',x===b)});var f=b.dataset.f;
document.querySelectorAll('.vuln').forEach(function(v){v.style.display=(f==='todos'||v.dataset.sev===f)?'':'none'})})});
"""


def generar(datos):
    datos = limpiar(datos)
    hallazgos = sorted(datos.get("hallazgos") or [],
                       key=lambda h: ORDEN.index(h.get("severidad")) if h.get("severidad") in ORDEN else 9)
    conteo = {s: sum(1 for h in hallazgos if h.get("severidad") == s) for s in ORDEN}
    total = sum(conteo.values())
    ver_txt, ver_cls = veredicto_auto(conteo)
    if datos.get("veredicto"):
        ver_txt = datos["veredicto"]
    proyecto = datos.get("proyecto") or "Tu proyecto"
    fecha = datos.get("fecha") or datetime.date.today().isoformat()

    p = []
    p.append('<!doctype html><html lang="es"><head><meta charset="utf-8">'
             '<meta name="viewport" content="width=device-width,initial-scale=1">'
             '<title>Reporte de seguridad · %s</title><style>%s</style></head><body><div class="wrap">' % (e(proyecto), CSS))
    p.append('<header><div class="marca">Reporte de seguridad</div><h1>%s</h1><div class="meta">%s · %s</div></header>'
             % (e(proyecto), e(fecha), " · ".join(e(x) for x in datos.get("revisado") or [])))

    # Veredicto + gráfico
    p.append('<section class="card"><div class="veredicto"><span class="punto" style="background:var(--%s)"></span>'
             '<div><h2>%s</h2><p>%s</p></div></div>' % (ver_cls, e(ver_txt), e(datos.get("resumen"))))
    p.append('<div class="barra" role="img" aria-label="%d problemas: %s">' %
             (total, ", ".join("%d %s" % (conteo[s], SEV[s][0].lower()) for s in ORDEN)))
    if total:
        for s in ORDEN:
            if conteo[s]:
                p.append('<span style="width:%.2f%%;background:var(--%s)"></span>' % (100.0 * conteo[s] / total, SEV[s][1]))
    else:
        p.append('<span style="width:100%;background:var(--ok)"></span>')
    p.append('</div><div class="conteos">')
    for s in ORDEN:
        p.append('<div class="conteo" style="box-shadow:inset 3px 0 0 var(--%s)"><b>%d</b><small>%s</small></div>'
                 % (SEV[s][1], conteo[s], SEV[s][0] + ("s" if conteo[s] != 1 else "")))
    p.append('</div></section>')

    # Haz esto hoy
    rotar = datos.get("rotar_hoy") or []
    if rotar:
        p.append('<section class="card hoy"><h2>Haz esto hoy: cambia estas llaves</h2>'
                 '<p>Estuvieron expuestas. Borrarlas del código no basta: ya pudieron ser copiadas. '
                 'Genera una nueva en cada servicio, desactiva la vieja y actualízala en tu hosting.</p><ul>')
        for r in rotar:
            p.append('<li><b>%s</b>: %s</li>' % (e(r.get("llave")), e(r.get("donde"))))
        p.append('</ul></section>')

    # Datos del servidor
    info = datos.get("servidor_info") or {}
    if info:
        p.append('<div class="seccion"><h2>Tu servidor</h2></div><section class="card"><div class="info">')
        for k, v in info.items():
            p.append('<div><small>%s</small><b>%s</b></div>' % (e(k), e(v)))
        p.append('</div></section>')

    # Hallazgos
    p.append('<div class="seccion"><h2>Problemas encontrados</h2>')
    if total:
        p.append('<div class="filtros"><button data-f="todos" aria-pressed="true">Todos · %d</button>' % total)
        for s in ORDEN:
            if conteo[s]:
                p.append('<button data-f="%s" aria-pressed="false">%s · %d</button>' % (s, SEV[s][0], conteo[s]))
        p.append('</div>')
    p.append('</div>')
    if not hallazgos:
        p.append('<div class="card vacio">No se encontraron problemas de seguridad en lo revisado.</div>')
    grupos = [g for g in ("servidor", "codigo") if any((h.get("grupo") or "codigo") == g for h in hallazgos)]
    if len(grupos) > 1:
        hallazgos = [h for g in grupos for h in hallazgos if (h.get("grupo") or "codigo") == g]
    grupo_actual = None
    for i, h in enumerate(hallazgos, 1):
        g = h.get("grupo") or "codigo"
        if len(grupos) > 1 and g != grupo_actual:
            grupo_actual = g
            p.append('<h3 class="grupo">%s</h3>' % ("Tu servidor" if g == "servidor" else "Tu código"))
        s = h.get("severidad") if h.get("severidad") in SEV else "baja"
        nombre, cls = SEV[s]
        p.append('<article class="card vuln" data-sev="%s" style="--c:var(--%s);--cbg:var(--%s-bg)">' % (s, cls, cls))
        etq = '<span class="etq">%s</span>' % ("Servidor" if g == "servidor" else "Código") if len(grupos) > 1 else ""
        p.append('<div class="cabeza"><h3>%d. %s%s</h3><span class="pill">%s</span></div>' % (i, e(h.get("titulo")), etq, nombre))
        if h.get("donde"):
            p.append('<span class="donde">%s</span>' % e(h["donde"]))
        p.append('<div class="dos"><div><h4>Qué pasa</h4><p>%s</p></div><div><h4>Qué podría hacer un atacante</h4><p>%s</p></div></div>'
                 % (e(h.get("que_pasa")), e(h.get("riesgo"))))
        if h.get("pasos"):
            p.append('<details><summary>Cómo arreglarlo paso a paso</summary><ol>%s</ol></details>'
                     % "".join("<li>%s</li>" % e(x) for x in h["pasos"]))
        pid = "prompt-%d" % i
        p.append('<div class="prompt"><div class="prompt-top"><span><b>Prompt para arreglarlo</b> · '
                 'Claude Code, Hermes o Codex</span><button class="copiar" data-for="%s">Copiar</button></div>'
                 '<pre id="%s">%s</pre></div></article>' % (pid, pid, e(construir_prompt(h, datos.get("proyecto"), datos.get("conexion")))))

    if datos.get("bien"):
        p.append('<div class="seccion"><h2>Lo que está bien</h2></div><section class="card"><ul class="lista">')
        for x in datos["bien"]:
            p.append('<li><span class="ic ok">✓</span><span>%s</span></li>' % e(x))
        p.append('</ul></section>')
    if datos.get("manual"):
        p.append('<div class="seccion"><h2>Revisa tú a mano</h2></div><section class="card"><ul class="lista check">')
        for x in datos["manual"]:
            p.append('<li><label><input type="checkbox"><span>%s</span></label></li>' % e(x))
        p.append('</ul></section>')
    if datos.get("limites"):
        p.append('<section class="card limites"><b>Límites de esta revisión.</b> %s Ninguna revisión garantiza seguridad al 100%%.</section>'
                 % " ".join(e(x) for x in datos["limites"]))
    p.append('<footer>Generado por el skill auditoria-seguridad-web · %s</footer></div><script>%s</script></body></html>'
             % (e(fecha), JS))
    return "".join(p)


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    with open(sys.argv[1], encoding="utf-8") as f:
        datos = json.load(f)
    salida = generar(datos)
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        f.write(salida)
    print("Reporte generado:", os.path.abspath(sys.argv[2]))


if __name__ == "__main__":
    main()
