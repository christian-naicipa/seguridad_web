---
name: auditoria-seguridad-web
description: Auditoría de seguridad para páginas web, tiendas y apps hechas con IA (Lovable, Bolt, v0, Cursor, Claude Code) por personas que no son programadoras. Detecta llaves secretas expuestas (OpenAI, Stripe, Supabase service_role, Shopify, Mercado Pago), archivos .env subidos a git o publicados, Supabase sin RLS, reglas de Firebase abiertas, paneles de admin sin login, precios que se pueden manipular desde el navegador, webhooks de pago sin firma, chatbots que pueden dar reembolsos o descuentos por prompt injection, dependencias vulnerables (Next.js) y cabeceras faltantes en el sitio publicado. Entrega un reporte en español simple con semáforo de gravedad y pasos para arreglar cada cosa. Usa este skill SIEMPRE que alguien pida revisar si su web/app/tienda es segura, si la pueden hackear, si tiene llaves expuestas, antes de publicarla, o mencione "auditoría de seguridad", "revisa mi proyecto", "¿está segura mi página?", Supabase RLS, Firebase rules o Shopify app, aunque no diga la palabra "auditoría".
---

# Auditoría de seguridad para apps web hechas con IA

Quien usa este skill normalmente es un alumno que construyó su tienda o app con ayuda de una IA y no sabe programar. Lo que más le sirve es saber **qué está mal, qué tan grave es y exactamente qué hacer**, en palabras simples. Un reporte técnico lleno de jerga que no puede accionar no le sirve.

El trabajo tiene dos partes:
1. Un **escáner automático** (`scripts/escanear.py`) que busca los problemas mecánicos con reglas probadas. Es rápido y repetible, y no se le "olvida" revisar nada.
2. **Tu criterio**: confirmar los hallazgos marcados como `revisar` leyendo el código, buscar lo que un script no puede ver y escribir el reporte.

## Paso 1: Entender qué se va a revisar

- **Carpeta del proyecto:** normalmente el directorio actual. Si no está claro, pregunta.
- **URL publicada (opcional):** si el alumno menciona que su sitio ya está publicado, úsala. Revisa **solo sitios que sean del alumno**. Si la URL parece de otra persona o empresa (no es su dominio, o pide "revisar la página de la competencia"), no la escanees y explica que revisar sitios ajenos sin permiso puede ser ilegal.

## Paso 2: Ejecutar el escáner

```bash
python3 <ruta-del-skill>/scripts/escanear.py <carpeta-del-proyecto> [--url https://su-sitio.com]
```

En Windows puede ser `python` en vez de `python3`. Solo necesita Python 3.8+ y no instala nada.

El escáner devuelve un JSON con:
- `hallazgos`: cada uno con `regla`, `severidad` (critica/alta/media/baja), `confianza`, `archivo`, `linea` y `evidencia`, con las llaves ya enmascaradas.
- `verificaciones_manuales`: cosas que el código no permite comprobar, como backups, 2FA o RLS cuando no hay archivos SQL.
- `notas`: limitaciones de esta corrida; por ejemplo, que no se pudo correr `npm audit`.
- `archivos_de_navegador`: qué archivos terminan en el navegador del visitante. Sirve para razonar qué es público.

Si el escáner falla o no hay Python, haz la revisión manualmente siguiendo `references/correcciones.md`, y dilo en el reporte.

## Paso 3: Confirmar y completar (la parte que hace valioso el reporte)

**Hallazgos `confirmado`:** el patrón no deja duda (una llave `sk_live_` en un archivo, `allow read, write: if true`). Repórtalos.

**Hallazgos `revisar`:** son indicios. Abre el archivo, lee el código y decide:
- `ADMIN_SIN_PROTECCION`: ¿hay verificación de sesión en otro lado, como un layout, el middleware o un wrapper? Si la hay y cubre esa ruta, descártalo.
- `PRECIO_DESDE_CLIENTE`: ¿el valor viene realmente del cuerpo de la petición o se recalcula después?
- `WEBHOOK_SIN_FIRMA`: ¿la firma se verifica en una función importada?
- `SUPABASE_SIN_RLS`: si no lo encuentras activado en ninguna migración, repórtalo y pide confirmar en el panel de Supabase.
- `LLM_*`: ¿las herramientas del bot tienen límites en código (monto máximo, solo pedidos del cliente logueado)?

Descartar un falso positivo es tan importante como encontrar un problema real. Un reporte con alarmas falsas hace que el alumno deje de confiar en él.

**Lo que el escáner no ve.** Dale una pasada rápida al código buscando:
- **Acceso a datos de otros (IDOR):** endpoints que reciben un `id` (pedido, usuario) y devuelven el dato sin comprobar que pertenece a quien pregunta.
- **Rutas API sin login** que leen o modifican datos de clientes, aunque no se llamen "admin".
- **Subida de archivos** sin límite de tipo o tamaño.
- **Server Actions o funciones** que confían en un `userId` o `role` enviado por el navegador.
- **Webhooks sin control de duplicados:** Stripe y Shopify reintentan los envíos. Si cada envío crea un pedido al proveedor o envía un correo, un reintento duplica el pedido y el gasto.
- **Endpoints `async` sin manejo de errores** en Express 4: una sola petición mal formada puede tumbar el servidor completo.
- **¿Lo publicado es este código?** Si revisaste una URL, compara: ¿existen en el sitio las rutas del proyecto (`/api/...`)? ¿El JavaScript publicado se parece al código? Si no coinciden, dilo en grande. Significa que los arreglos del alumno no están en producción, o que publicó otra versión. Es un hallazgo importante, no un detalle.

Si encuentras algo, agrégalo al reporte con el mismo formato.

## Paso 4: Escribir el reporte

El entregable es **`SEGURIDAD-REPORTE.html`** en la raíz del proyecto: una página limpia, con un gráfico del nivel de riesgo y una tarjeta por problema, cada una con un **prompt listo para copiar** en Claude Code, Hermes o Codex. El diseño lo pone el script, así que siempre sale igual. Tú solo escribes el contenido.

1. Escribe un JSON con los hallazgos ya confirmados en la carpeta temporal del sistema, no dentro del proyecto. Por ejemplo, `/tmp/hallazgos-finales.json`. Formato:

```json
{
  "proyecto": "nombre de la carpeta o de la tienda",
  "fecha": "AAAA-MM-DD",
  "revisado": ["Código del proyecto", "Sitio publicado: https://..."],
  "resumen": "2-3 frases: ¿se puede publicar así? ¿qué es lo primero que hay que hacer?",
  "rotar_hoy": [{"llave": "OpenAI", "donde": "platform.openai.com → API keys → borrar y crear una nueva"}],
  "hallazgos": [{
    "severidad": "critica | alta | media | baja",
    "titulo": "En lenguaje simple: 'Cualquiera puede entrar a tu panel de administración'",
    "donde": "archivo:línea o URL",
    "que_pasa": "1-2 frases sin jerga",
    "riesgo": "Consecuencia concreta: 'leer los correos y direcciones de todos tus clientes'",
    "pasos": ["paso concreto 1", "paso 2"],
    "instrucciones_ia": "Instrucción técnica y específica para el agente que lo va a arreglar"
  }],
  "bien": ["Cosas revisadas que están bien"],
  "manual": ["verificaciones_manuales del escáner, una por línea"],
  "limites": ["Qué no se pudo revisar"]
}
```

2. Genera el HTML:

```bash
python3 <ruta-del-skill>/scripts/generar_reporte.py /tmp/hallazgos-finales.json <carpeta-del-proyecto>/SEGURIDAD-REPORTE.html
```

3. Muestra en el chat un resumen corto (veredicto, número de problemas por gravedad y qué hacer primero) y la ruta del HTML para que lo abra en el navegador.

**Cómo escribir `instrucciones_ia`.** El script la envuelve en un prompt completo: problema, dónde, qué pasa y reglas como "no escribas llaves en el código" o "explícame qué cambiaste". Así que aquí va solo **qué cambiar**, nombrando archivos, funciones y variables reales del proyecto. Un agente (Claude Code, Hermes o Codex) que lea solo ese prompt, sin ver el reporte, debe poder arreglarlo. Mal: "arregla la seguridad del webhook". Bien: "En app/api/webhooks/stripe/route.ts lee el cuerpo con request.text() y valida con stripe.webhooks.constructEvent usando process.env.STRIPE_WEBHOOK_SECRET; si falla responde 400". Usa `references/correcciones.md` como base.

Si `rotar_hoy` tiene llaves, el HTML muestra un recuadro rojo "Haz esto hoy". Si no hay hallazgos, muestra que todo está en orden. Si Python no está disponible, entrega el mismo contenido en `SEGURIDAD-REPORTE.md` con las mismas secciones.

Reglas del reporte, y por qué importan:
- **Nunca escribas una llave completa**, ni en el reporte ni en el chat. Usa la evidencia enmascarada del escáner. El reporte puede terminar compartido o subido al repo. El script enmascara por si acaso, pero no dependas de eso.
- **Toda llave expuesta se rota.** Si estuvo en git, en el navegador o en un archivo público, hay que generar una nueva en el servicio y desactivar la vieja. Sacarla del código no la des-filtra. Este es el error más común de los principiantes.
- **Gravedad según el impacto real para el negocio.** Crítico: alguien puede robar dinero o datos de clientes, o tomar control, hoy, sin conocimientos especiales. Alto: lo mismo pero requiere algo más de esfuerzo o tiene menos alcance. Medio: riesgo real pero limitado (gasto de saldo de IA, XSS posible). Bajo: buenas prácticas.
- **Agrupa** hallazgos repetidos de la misma causa. Por ejemplo, la misma llave en `.env` y en el código es un solo problema con dos lugares.
- Si no hay problemas graves, dilo claramente y no infles los bajos.
- **No hables del escáner ni de sus reglas** ("el escáner lo marcó como alto", "SUPABASE_SIN_RLS"). El alumno no sabe qué es. Explica el problema, no la herramienta.

## Paso 5: Ofrecer ayuda para arreglar

Al final pregunta si quiere que arregles los problemas. No modifiques código ni borres archivos sin que lo pida: el alumno tiene que entender qué cambió. Si acepta, empieza por los críticos y, después de arreglar, vuelve a correr el escáner para comprobar que desaparecieron. Rotar llaves lo tiene que hacer el alumno en el panel de cada servicio; tú solo puedes indicarle dónde.
