# Auditoría de seguridad para tu web (skill para Claude)

Revisa si tu página, tienda o app hecha con IA (Lovable, Bolt, v0, Cursor, Claude Code) se puede hackear. Te entrega un **reporte visual en HTML** con:
- Cada problema explicado en palabras simples.
- Qué podría hacer un atacante.
- **Un prompt listo para copiar** en Claude Code, Hermes o Codex para que lo arregle.

Está pensado para quienes **no son programadores**.

![Reporte de seguridad](docs/captura-reporte.jpg)

## Descargar

**[⬇ Descargar auditoria-seguridad-web.skill](https://github.com/christian-naicipa/seguridad_web/raw/main/auditoria-seguridad-web.skill)**

Es un archivo `.zip` con la carpeta `auditoria-seguridad-web/`. También puedes descargar ese código directamente desde este repositorio.

## Instalar

### Opción A: Claude Code (recomendada)
Claude puede revisar la carpeta de tu proyecto directamente.

Mac o Linux:
```bash
unzip auditoria-seguridad-web.skill -d ~/.claude/skills/
```

Windows: descomprime el archivo dentro de `C:\Users\<tu-usuario>\.claude\skills\`.

### Opción B: claude.ai o la app de Claude
1. En la configuración, ve a la sección de skills y sube el archivo `.skill`. Necesita tener activada la ejecución de código.
2. Sube tu proyecto en un `.zip` en el chat, porque Claude no ve las carpetas de tu computadora.

**Requisito:** Python 3.8 o más reciente. En Mac ya viene instalado; en Windows se instala desde [python.org](https://www.python.org/downloads/). No instala nada más.

## Usar

Abre Claude Code en la carpeta de tu proyecto y escribe algo como:

> revisa si mi tienda es segura, está publicada en https://mitienda.com

o simplemente *"¿me pueden hackear?"*. El skill se activa solo.

Vas a recibir:
1. **`SEGURIDAD-REPORTE.html`** en tu proyecto. Ábrelo en el navegador:
   - Un veredicto (¿la puedo publicar?) y un gráfico de problemas por gravedad.
   - **Haz esto hoy:** qué llaves cambiar y dónde se cambian.
   - Una tarjeta por problema con el botón **Copiar prompt**.
   - Lo que está bien, una lista para revisar a mano y los límites de la revisión.
2. Un resumen corto en el chat.
3. Una oferta para arreglarlo. Claude no modifica tu código sin permiso.

![Prompts por problema](docs/captura-prompts.jpg)

Puedes ver un ejemplo en [`ejemplo/reporte-ejemplo.html`](ejemplo/reporte-ejemplo.html): descárgalo y ábrelo en tu navegador.

## Qué revisa

| Tema | Ejemplos |
|---|---|
| Llaves expuestas | OpenAI, Claude, Stripe, Supabase `service_role`, Shopify, Mercado Pago, AWS, GitHub, Telegram, en el código o en el JavaScript publicado |
| Archivos `.env` | Subidos a git (incluso en el historial), publicados en el sitio o con prefijo público (`NEXT_PUBLIC_`, `VITE_`) |
| Base de datos | Supabase sin RLS o con políticas `true`, Firebase con `if true` o en modo de prueba |
| Accesos | Paneles `/admin` sin login, endpoints que borran usuarios o crean descuentos sin verificación |
| Pagos | Precio que viene del navegador, webhooks de Stripe, Shopify o Mercado Pago sin verificar la firma |
| Chatbots con IA | Bots que pueden dar reembolsos o cupones, prompt injection, endpoints sin límite de uso |
| Dependencias | Next.js con vulnerabilidades conocidas, `npm audit` |
| Sitio publicado | `/.env` y `/.git` expuestos, HTTPS, cabeceras de seguridad, source maps |

Lo que no se puede ver en el código (backups, verificación en dos pasos, el panel de Supabase) aparece como una lista para revisar a mano.

**En el sitio publicado solo hace lecturas** (peticiones GET). No ataca nada y no revisa sitios que no sean tuyos.

## Cómo funciona

1. **`scripts/escanear.py`** busca los problemas con reglas fijas y repetibles. Las llaves que encuentra salen enmascaradas.
2. **Claude** confirma cada hallazgo leyendo el código, descarta las falsas alarmas y busca lo que un script no ve, como el acceso a datos de otros usuarios.
3. **`scripts/generar_reporte.py`** arma el HTML con un diseño fijo, sin depender de internet. Escapa todo el texto y enmascara cualquier llave que se haya colado.

## Pruebas

Las pruebas crean apps con vulnerabilidades plantadas:
- Next.js con Supabase.
- Firebase con un chatbot.
- Una app de Shopify.
- Una tienda bien hecha, para medir falsas alarmas.
- Dos sitios publicados de prueba.

Luego verifican que el escáner detecte todo, que no dé falsas alarmas y que el reporte nunca muestre llaves completas.

```bash
python3 pruebas/test_escanear.py
```

Todas las llaves de las pruebas son falsas.

También se comparó Claude con y sin el skill sobre 4 casos:

| | Con skill | Sin skill |
|---|---|---|
| Revisiones correctas | **38/38 (100%)** | 35/38 (92%) |
| Muestra llaves completas | Nunca | Una vez |

## Límites

Ninguna herramienta garantiza seguridad al 100%. El skill revisa los errores más comunes en proyectos hechos con IA. No reemplaza una auditoría profesional si manejas pagos o datos sensibles a gran escala.
