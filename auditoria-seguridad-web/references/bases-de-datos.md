# Diagnóstico de la base de datos según el motor

El escáner devuelve `bases_de_datos` con `motores` (supabase, firebase, postgresql, sqlserver, mysql, mongodb), `api_directa` (Supabase, PostgREST, Hasura), `evidencia` y `modelo`. **Antes de hablar de la base de datos, lee `modelo`.** El diagnóstico correcto depende de una sola pregunta: ¿quién habla con la base?

| Situación | Quién habla con la base | Qué la protege | ¿Aplica RLS? |
|---|---|---|---|
| Supabase, PostgREST o Hasura | **El navegador**, con una llave pública | Las reglas por fila (RLS) y las políticas | **Sí, es la protección principal** |
| Firebase | El navegador | Las reglas de seguridad (`firestore.rules`) | No: son "reglas" |
| PostgreSQL, SQL Server o MySQL usados desde tu backend (Express, Next API, Django, .NET, PHP) | **Solo tu servidor** | Contraseña secreta, consultas con parámetros, usuario con permisos mínimos, puerto cerrado, conexión cifrada | **No es la protección principal**. No reportes "falta RLS" |
| Supabase usado también con conexión directa (`DATABASE_URL`) | Ambos | Las dos cosas | Sí, más las reglas de SQL |

**Error que hay que evitar:** decirle a un alumno con PostgreSQL o SQL Server "activa RLS en tus tablas". Lo pone a trabajar en algo que no lo protege y deja sin ver lo que sí importa. RLS en Postgres directo solo se recomienda como capa extra en apps multi-cliente avanzadas, nunca como hallazgo.

**Cómo explicárselo al alumno:**
- Supabase: "tu página habla directo con la base de datos, así que cada tabla necesita su cerradura".
- Postgres o SQL Server: "tu página nunca toca la base; solo tu servidor. El peligro es que alguien robe la contraseña de la base o engañe a tu servidor para que haga consultas que no debe".

---

## Hallazgos de bases SQL (PostgreSQL, SQL Server, MySQL)

### SQL_INYECCION (crítico si se confirma)
- **Confirma** leyendo el código: ¿el texto pegado en la consulta viene del cliente (`req.query`, `req.body`, `req.params`, un formulario)? Si es una constante del código (un nombre de tabla fijo), descártalo.
- **Para el alumno:** "Tu tienda arma la pregunta a la base pegando lo que escribe el cliente. Alguien puede escribir un truco como `' OR '1'='1` en el buscador o en el login y ver todos tus clientes, entrar sin contraseña o borrar tablas."
- **Arreglo:** consultas con parámetros; el valor nunca se pega en el texto.
  - **node-postgres:** `pool.query('SELECT … WHERE email = $1', [email])`
  - **postgres.js, @vercel/postgres o Drizzle:** sql`SELECT … WHERE email = ${email}` (la etiqueta `sql` delante del texto lo protege).
  - **mssql:** `request.input('email', sql.NVarChar, email).query('SELECT … WHERE Email = @email')`
  - **mysql2:** `conn.execute('SELECT … WHERE email = ?', [email])`
  - **Prisma:** `$queryRaw` con la etiqueta, nunca `$queryRawUnsafe` con texto armado.
  - **Python:** `cursor.execute("… WHERE email = %s", (email,))`, nunca f-strings.
  - **C#:** `cmd.Parameters.AddWithValue("@email", email)`, nunca `$"…{email}"`.
  - **PHP:** PDO con `prepare` y `execute([$email])`.
- `instrucciones_ia`: "En [archivo:línea] la consulta pega [variable] dentro del SQL. Reescríbela con parámetros ([$1 / @param / ?] según el driver) y revisa el resto del proyecto buscando otras consultas armadas con + o con ${}. No cambies lo que hace la consulta."

### SECRETO_EN_CODIGO (dirección `postgres://…` o cadena `Server=…;Password=…`) y BD_CREDENCIALES_EN_CODIGO
- La dirección de la base lleva usuario y contraseña: es una llave de caja fuerte.
- **Arreglo:**
  1. Cambiar la contraseña del usuario en la base: `ALTER ROLE app WITH PASSWORD '…'` en Postgres, `ALTER LOGIN app WITH PASSWORD = '…'` en SQL Server.
  2. Moverla a una variable de entorno (`DATABASE_URL`) que no se suba a git.
  3. Si estuvo en git, considerarla robada aunque se borre.

### BD_DESDE_NAVEGADOR
- La página importa el driver de la base (`pg`, `mssql`, `mysql2`, Prisma). Para conectarse necesita la contraseña, y entonces todos la tienen.
- **Arreglo:** mover las consultas a rutas de API del servidor.

### BD_USUARIO_ADMIN (`postgres`, `sa`, `root`)
- Con el administrador, un solo error (inyección o conexión robada) da control de toda la base. En SQL Server con `sa`, o en Postgres con superusuario, a veces también del sistema operativo.
- **Arreglo, PostgreSQL:**
  ```sql
  CREATE ROLE app_tienda LOGIN PASSWORD '<larga>';
  GRANT CONNECT ON DATABASE tienda TO app_tienda;
  GRANT USAGE ON SCHEMA public TO app_tienda;
  GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_tienda;
  GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO app_tienda;
  ```
- **Arreglo, SQL Server:**
  ```sql
  CREATE LOGIN app_tienda WITH PASSWORD = '<larga>';
  USE Tienda; CREATE USER app_tienda FOR LOGIN app_tienda;
  ALTER ROLE db_datareader ADD MEMBER app_tienda; ALTER ROLE db_datawriter ADD MEMBER app_tienda;
  ```
  Luego desactivar `sa`: `ALTER LOGIN sa DISABLE`.
- **Arreglo, MySQL:** `CREATE USER 'app'@'localhost' …; GRANT SELECT, INSERT, UPDATE, DELETE ON tienda.* TO 'app'@'localhost';`

### BD_PERMISOS_EXCESIVOS / BD_XP_CMDSHELL
- **`xp_cmdshell`:** ejecuta comandos del sistema desde SQL Server, así que una inyección se convierte en control del servidor. Se apaga con `EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`.
- **`sysadmin` / `db_owner` / `SUPERUSER` / `GRANT ALL … TO PUBLIC`:** reemplazar por los permisos mínimos de arriba.

### BD_SIN_CIFRADO
- Solo importa si la base está en **otro** servidor (Neon, RDS, Azure SQL o un VPS distinto). En ese caso:
  - Postgres: `sslmode=require` o `ssl: 'require'`.
  - SQL Server: `Encrypt=True;TrustServerCertificate=False`.
- Si la base está en el mismo servidor o en la misma red de Docker, bájalo a bajo o descártalo.

### BD_PUERTO_PUBLICADO / BD_PASSWORD_EN_COMPOSE / BD_PASSWORD_EN_SQL
- **Puertos:** `"5432:5432"` publica la base a internet en el VPS, y Docker se salta ufw. Hay que usar `"127.0.0.1:5432:5432"` o quitar `ports`.
- **Contraseñas:** van en un `.env` no versionado (`POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}`), y la que estaba en el repo se cambia.

## En el VPS (escanear_servidor.py)

- **PG_TRUST_REMOTO (crítico):** `pg_hba.conf` con `trust` para direcciones remotas deja entrar sin contraseña. Cambiar a `scram-sha-256` y limitar la dirección a `127.0.0.1/32` o a la IP de la app. Recargar con `sudo systemctl reload postgresql`.
- **PG_ACCESO_DESDE_INTERNET:** `0.0.0.0/0` en `pg_hba.conf` acepta intentos desde todo internet. Limitar la dirección. Combinado con el puerto 5432 abierto (BD_EXPUESTA), es crítico.
- **PG_TRUST_LOCAL / PG_PASSWORD_PLANO:** cambiar a `scram-sha-256`.
- **SQL Server en el VPS:**
  - Puerto 1433 cerrado a internet.
  - `sa` desactivado.
  - Para revisarlo desde el panel: `mssql-conf` o `SELECT name, is_disabled FROM sys.sql_logins`.

## MongoDB (si aparece)

Solo el servidor debe conectarse, con usuario y contraseña activos y el puerto 27017 cerrado. Cuidado con filtros armados con datos del usuario: `{ email: req.body.email }`, si `email` llega como objeto `{"$ne": null}`, devuelve todo. Hay que validar que sea texto.
