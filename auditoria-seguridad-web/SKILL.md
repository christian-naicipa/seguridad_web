---
name: auditoria-seguridad-web
description: Auditoría de seguridad para webs, tiendas, apps y servidores VPS hechos con IA (Lovable, Bolt, Cursor, Claude Code) por personas que no programan. Revisa el código (llaves de OpenAI/Stripe/Supabase/Shopify expuestas, .env en git, Supabase sin RLS, Firebase abierto, admin sin login, precios manipulables, webhooks sin firma, chatbots con reembolsos), el sitio publicado y el VPS por SSH (bases de datos o paneles abiertos a internet, Docker saltándose el firewall, SSH con contraseña, parches, mineros y malware, backups). Entrega un reporte HTML visual con un prompt para corregir cada falla con Claude Code, Hermes o Codex. Úsalo SIEMPRE que pidan revisar si su web, app, tienda o servidor es segura, si la pueden hackear, si tiene llaves expuestas, antes de publicar, o mencionen "auditoría", "revisa mi VPS", "mi servidor", "¿está segura mi página?", Supabase RLS, Firebase rules o Shopify app.
---

# Auditoría de seguridad para apps web hechas con IA

Quien usa este skill normalmente es un alumno que construyó su tienda o app con ayuda de una IA y no sabe programar. Lo que más le sirve es saber **qué está mal, qué tan grave es y exactamente qué hacer**, en palabras simples. Un reporte técnico lleno de jerga que no puede accionar no le sirve.

El trabajo tiene dos partes:
1. Un **escáner automático** (`scripts/escanear.py`) que busca los problemas mecánicos con reglas probadas. Es rápido y repetible, y no se le "olvida" revisar nada.
2. **Tu criterio**: confirmar los hallazgos marcados como `revisar` leyendo el código, buscar lo que un script no puede ver y escribir el reporte.

## Paso 1: Entender qué se va a revisar

- **Carpeta del proyecto:** normalmente el directorio actual. Si no está claro, pregunta.
- **URL publicada (opcional):** si el alumno menciona que su sitio ya está publicado, úsala. Revisa **solo sitios que sean del alumno**. Si la URL parece de otra persona o empresa (no es su dominio, o pide "revisar la página de la competencia"), no la escanees y explica que revisar sitios ajenos sin permiso puede ser ilegal.

- **VPS o servidor (opcional):** si el alumno dice que su app está en un VPS, servidor, Hetzner, DigitalOcean, Hostinger, Contabo, AWS, etc., haz también la **revisión del servidor** (ver "Modo VPS" más abajo). Ahí se ve el 100% del código de producción y la configuración del servidor, que desde una URL no se puede ver.

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
- `bases_de_datos`: qué motor usa el proyecto (Supabase, Firebase, PostgreSQL, SQL Server, MySQL, MongoDB), si el navegador habla directo con la base (`api_directa`) y un texto `modelo` que explica qué la protege. Úsalo para el diagnóstico de la base de datos (ver Paso 3).

Si el escáner falla o no hay Python, haz la revisión manualmente siguiendo `references/correcciones.md`, y dilo en el reporte.

## Modo VPS: revisar el servidor y el código de producción

Necesitas cómo se conecta el alumno: `usuario@IP` (o el alias de su `~/.ssh/config`), el puerto si no es 22 y, si lo sabe, en qué carpeta está la app. **Antes de conectarte, confírmale qué vas a hacer:** "Me voy a conectar a tu servidor solo para leer. No cambio nada. Subo dos archivos a una carpeta temporal y la borro al terminar." Conéctate solo a servidores del alumno.

**Opción A, desde la computadora del alumno (la normal):**

```bash
python3 <ruta-del-skill>/scripts/auditar_vps.py usuario@IP [-p 22] [-i ~/.ssh/llave] [--app /var/www/mi-tienda]
```

El script:
1. Entra por SSH.
2. Revisa el servidor (con `sudo` si está disponible sin contraseña).
3. Encuentra las apps (`/var/www`, `/opt`, `/srv`, `/home`) y revisa su código con el mismo escáner. Si no pasas `--app`, revisa hasta 5 de las que encuentre.
4. Desde la computadora del alumno prueba si los puertos delicados responden desde internet. Si un puerto responde, el problema queda confirmado; si no responde, baja a medio y queda marcado como "revisar".
5. Borra todo lo que subió.

Devuelve un JSON con `servidor` (hallazgos + `inventario`), `apps` (un resultado de `escanear.py` por app), `puertos_desde_internet` y `notas`.

Si devuelve `error`:
- `no_se_pudo_conectar`: el script entra con llave SSH, nunca escribe contraseñas. Si el alumno solo tiene contraseña, pídele que ejecute **él** en su terminal `ssh-copy-id usuario@IP` y vuelve a intentar. Nunca le pidas su contraseña ni la escribas tú.
- `sin_python`: el VPS no tiene python3. Que lo instale con `sudo apt install -y python3`.

**Opción B, Claude Code o Hermes corriendo dentro del VPS:**

```bash
sudo python3 <ruta-del-skill>/scripts/escanear_servidor.py
python3 <ruta-del-skill>/scripts/escanear.py /var/www/mi-tienda
```

**Al confirmar los hallazgos del servidor** usa `references/servidor.md`:
- **Señales de compromiso** (minero, cron con `curl | sh`, `ld.so.preload`, usuario con UID 0): son lo primero del reporte. Confirma leyendo la evidencia antes de afirmar un ataque, porque un script propio del alumno en `/tmp` puede ser legítimo. Si es real, el reporte debe decir claramente que el servidor está comprometido y seguir el plan de esa guía.
- **Puertos:** `desde_internet: "abierto"` confirma el problema; `"cerrado"` significa que lo bloquea otro firewall.
- El inventario tiene datos para el reporte: sistema, puertos públicos, contenedores e intentos de entrar por SSH en las últimas 24 horas. Este último dato impresiona y educa.

**Nunca hagas cambios en el servidor durante la auditoría**, aunque sean "obvios". Si el alumno después pide arreglarlos, sigue el orden de `references/servidor.md`: respaldo, cambio, validar, recargar y probar el acceso en otra conexión. Sobre todo con SSH y el firewall, porque un error lo deja fuera de su propio servidor.

## Paso 3: Confirmar y completar (la parte que hace valioso el reporte)

**Hallazgos `confirmado`:** el patrón no deja duda (una llave `sk_live_` en un archivo, `allow read, write: if true`). Repórtalos.

**Hallazgos `revisar`:** son indicios. Abre el archivo, lee el código y decide:
- `ADMIN_SIN_PROTECCION`: ¿hay verificación de sesión en otro lado, como un layout, el middleware o un wrapper? Si la hay y cubre esa ruta, descártalo.
- `PRECIO_DESDE_CLIENTE`: ¿el valor viene realmente del cuerpo de la petición o se recalcula después?
- `WEBHOOK_SIN_FIRMA`: ¿la firma se verifica en una función importada?
- `SUPABASE_SIN_RLS` / `BD_SIN_RLS`: si no lo encuentras activado en ninguna migración, repórtalo y pide confirmar en el panel.
- `SQL_INYECCION`: confirma que el texto pegado en la consulta viene del cliente (`req.query`, `req.body`, un formulario). Si es una constante del código, descártalo.

**Diagnóstico de la base de datos: depende del motor.** Lee `bases_de_datos.modelo` y `references/bases-de-datos.md` antes de escribir sobre la base.
- **Supabase, PostgREST o Hasura:** el navegador consulta la base directo, así que **RLS y las políticas son la protección principal**.
- **Firebase:** la protección son las reglas de seguridad.
- **PostgreSQL, SQL Server o MySQL usados desde el backend:** solo el servidor de la app se conecta. **No digas "falta RLS" ni recomiendes activarlo.** Revisa lo que de verdad protege:
  - que la contraseña de la base no esté en el código ni en git;
  - que las consultas usen parámetros (inyección SQL);
  - que la app no use `postgres`, `sa` o `root`;
  - que el puerto no esté abierto a internet;
  - que la conexión vaya cifrada si la base está en otro servidor.
- Nombra el motor real en el reporte ("tu base PostgreSQL", "tu SQL Server"), con los pasos y comandos de ese motor.
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
  "conexion": "ssh deploy@203.0.113.10   (solo en modo VPS: se usa en los prompts del servidor)",
  "servidor_info": {"Sistema": "Ubuntu 22.04", "Puertos abiertos a internet": "22, 80, 443, 5432",
                    "Intentos de entrar por SSH (24 h)": "18.342", "Contenedores": "4"},
  "hallazgos": [{
    "severidad": "critica | alta | media | baja",
    "titulo": "En lenguaje simple: 'Cualquiera puede entrar a tu panel de administración'",
    "donde": "archivo:línea o URL",
    "que_pasa": "1-2 frases sin jerga",
    "riesgo": "Consecuencia concreta: 'leer los correos y direcciones de todos tus clientes'",
    "pasos": ["paso concreto 1", "paso 2"],
    "instrucciones_ia": "Instrucción técnica y específica para el agente que lo va a arreglar",
    "grupo": "codigo | servidor"
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

3. **Entrega el HTML dentro del chat, como archivo adjunto.** No le digas al alumno que vaya a una carpeta a buscarlo. Según dónde estés:
   - **Claude (app de escritorio, Cowork, claude.ai):** usa la herramienta para enviar archivos al usuario (`SendUserFile`, `present_files` o la que tenga tu entorno) con la ruta del HTML.
   - **Hermes en Telegram, Discord, Slack, WhatsApp o Signal:** escribe en tu respuesta una línea propia con `MEDIA:` seguido de la ruta absoluta del archivo, por ejemplo: MEDIA:/root/tienda/SEGURIDAD-REPORTE.html. Escríbela como texto normal, sin comillas invertidas ni bloque de código, porque Hermes ignora las rutas que están dentro de código. El gateway de Hermes lo detecta y lo sube como adjunto. Si Hermes corre con terminal en Docker, el archivo tiene que estar en una ruta que el gateway pueda leer en el servidor (por ejemplo dentro de `~/.hermes/`). Si no, cópialo ahí antes.
   - **Solo si tu entorno no puede enviar archivos** (por ejemplo, una terminal sin adjuntos), da la ruta y cómo abrirlo, y ofrece pegar el resumen en el chat.

   Junto al archivo, escribe un resumen corto: el veredicto, el número de problemas por gravedad y qué hacer primero.

**Cómo escribir `instrucciones_ia`.** El script la envuelve en un prompt completo: problema, dónde, qué pasa y reglas como "no escribas llaves en el código" o "explícame qué cambiaste". Así que aquí va solo **qué cambiar**, nombrando archivos, funciones y variables reales del proyecto. Un agente (Claude Code, Hermes o Codex) que lea solo ese prompt, sin ver el reporte, debe poder arreglarlo. Mal: "arregla la seguridad del webhook". Bien: "En app/api/webhooks/stripe/route.ts lee el cuerpo con request.text() y valida con stripe.webhooks.constructEvent usando process.env.STRIPE_WEBHOOK_SECRET; si falla responde 400". Usa `references/correcciones.md` como base.

En modo VPS, marca cada hallazgo con `"grupo": "servidor"` o `"grupo": "codigo"`. El HTML los separa en "Tu servidor" y "Tu código", y los prompts del servidor incluyen reglas para no perder el acceso. `servidor_info` muestra un resumen del servidor, con 3 a 5 datos simples sacados del inventario.

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
