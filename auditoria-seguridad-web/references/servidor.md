# Guía de corrección: servidor (VPS)

Cada sección dice qué explicarle al alumno y qué debe hacer el agente (`instrucciones_ia`).

**Regla de oro en servidores:** cambiar SSH o el firewall mal hecho deja al alumno fuera de su propio VPS. Siempre se hace en este orden:
1. Copia de respaldo del archivo.
2. El cambio.
3. Validar la sintaxis (`sshd -t`, `nginx -t`).
4. Recargar.
5. **Probar el acceso en una segunda conexión antes de cerrar la actual.**

Si el alumno pierde el acceso, puede entrar por la consola web de su proveedor (Hetzner, DigitalOcean, Hostinger tienen una).

## Índice
- Si hay señales de que ya te hackearon: PROCESO_SOSPECHOSO, CPU_ALTA, EJECUTABLE_EN_TMP, CRON_SOSPECHOSO, LD_PRELOAD, SERVICIO_SOSPECHOSO, USUARIO_UID0
- Puertos y Docker: BD_EXPUESTA, DOCKER_BD_PUBLICA, PANEL_EXPUESTO, DOCKER_PANEL_PUBLICO, DOCKER_API_EXPUESTA, BD_ESCUCHA_PUBLICA, PANEL_ESCUCHA_PUBLICA, DOCKER_SOCKET_MONTADO, DOCKER_PRIVILEGIADO, DOCKER_MONTA_SISTEMA
- Acceso: SSH_ROOT_CON_PASSWORD, SSH_CON_PASSWORD, SSH_ROOT, SIN_FAIL2BAN, USUARIO_SIN_PASSWORD
- Firewall: FIREWALL_INACTIVO
- Mantenimiento: PARCHES_PENDIENTES, REINICIO_PENDIENTE, SIN_ACTUALIZACIONES_AUTO, SO_SIN_SOPORTE, DISCO_LLENO
- Archivos y web: ENV_LEGIBLE, NGINX_SIRVE_OCULTOS, NGINX_VERSION
- Recuperación: SIN_BACKUP, CERTIFICADO_VENCIDO, CERTIFICADO_POR_VENCER

---

## Señales de que el servidor ya fue hackeado

Si aparece cualquiera de estas, **ese es el problema número uno del reporte**, por encima de todo lo demás:
- PROCESO_SOSPECHOSO
- CRON_SOSPECHOSO
- LD_PRELOAD
- SERVICIO_SOSPECHOSO
- USUARIO_UID0
- Un EJECUTABLE_EN_TMP que no se reconoce

Antes de afirmar que hubo un ataque, confirma leyendo el detalle. Un minero llamado `kdevtmpfsi` corriendo desde `/tmp/.x` y una tarea programada con `curl … | sh` no dejan dudas. Un script de deploy del propio alumno en `/tmp` sí puede ser legítimo.

**Qué decirle al alumno, sin alarmismo pero claro:** "Encontramos señales de que alguien más tiene control de tu servidor. Borrar el programa no basta: los atacantes dejan varias formas de volver a entrar."

**Plan recomendado:**
1. **No borres nada todavía.** Toma un snapshot del VPS desde el panel del proveedor, como evidencia y respaldo.
2. Desde **otra computadora segura**, cambia las contraseñas de:
   - el panel del proveedor del VPS;
   - el correo;
   - GitHub.

   Activa la verificación en dos pasos en todas.
3. **Rota todas las llaves** que estaban en el servidor: archivos `.env`, la base de datos, Stripe, OpenAI y las llaves SSH.
4. **Lo más seguro es un VPS nuevo:**
   - Instálalo limpio y endurécelo con esta guía.
   - Despliega el código desde git, no copiándolo del servidor infectado.
   - Restaura los datos desde un backup anterior al ataque.
   - Apaga el servidor viejo.
5. Si no puede migrar de inmediato, limpia como medida temporal:
   - Mata el proceso y borra el binario.
   - Borra la línea de cron, la unidad de systemd y `/etc/ld.so.preload`.
   - Elimina el usuario con UID 0.
   - Revisa `authorized_keys`.
   - Cierra el puerto por el que entraron. La causa más común es una base de datos expuesta, una contraseña de SSH débil o una app vulnerable.
6. Averigua por dónde entraron. Si no se arregla esa puerta, vuelven a entrar.

`instrucciones_ia` (limpieza temporal): "Primero crea una carpeta /root/incidente y guarda una copia de: el binario sospechoso, la línea de cron, la unidad de systemd y /etc/ld.so.preload. Muéstrame cada cosa que vas a borrar y espera mi confirmación. Luego: detén y deshabilita la unidad, mata el proceso, borra el binario, la línea de cron y /etc/ld.so.preload, y elimina el usuario con UID 0 distinto de root. Finalmente lista los archivos modificados en los últimos 7 días en /etc, /usr/bin, /usr/local/bin y /tmp, y dime qué más parece sospechoso."

---

## Puertos y Docker

### BD_EXPUESTA / DOCKER_BD_PUBLICA
- **Qué pasa:** PostgreSQL, MySQL, Redis o MongoDB se pueden alcanzar desde internet.
- **Riesgo:** los bots buscan estas bases de datos todo el día. Prueban contraseñas, y en Redis o MongoDB muchas veces ni hace falta. Después roban los datos o los borran y piden rescate.
- **Arreglo (base de datos instalada en el sistema):**
  - PostgreSQL: en `postgresql.conf` poner `listen_addresses = 'localhost'`.
  - MySQL: en `mysqld.cnf` poner `bind-address = 127.0.0.1`.
  - Redis: `bind 127.0.0.1` y `protected-mode yes`.
  - Luego reiniciar el servicio.
- **Arreglo (Docker):** en `docker-compose.yml` cambiar `"5432:5432"` por `"127.0.0.1:5432:5432"`. Si solo la usan otros contenedores, quitar `ports:` por completo: se comunican por la red interna de Docker. Luego `docker compose up -d`.
- **Lo que casi nadie sabe:** Docker abre los puertos publicados directamente en iptables. Por eso **ufw no los bloquea** aunque diga que están cerrados.
- `instrucciones_ia`: "Busca dónde se publica el puerto [N] (docker-compose.yml, docker run o la configuración del servicio). Si es Docker, cámbialo a 127.0.0.1:[N]:[N] o elimina 'ports' si solo lo usan otros contenedores. Si es un servicio del sistema, haz que escuche solo en 127.0.0.1. Verifica después con 'ss -tlnp | grep [N]' que ya no aparezca en 0.0.0.0, y comprueba que la app sigue conectándose a la base."

### PANEL_EXPUESTO / DOCKER_PANEL_PUBLICO
- Paneles como n8n, Portainer, Coolify, EasyPanel, pgAdmin o Webmin, publicados en su puerto directo.
- **Arreglo, según el caso:**
  - Si el panel debe ser accesible, ponerlo detrás del proxy (nginx, Traefik o Caddy) con HTTPS en un subdominio, con login fuerte y 2FA si lo tiene, y publicar su puerto solo en 127.0.0.1.
  - Si lo usa solo el alumno, entrar por túnel SSH: `ssh -L 5678:localhost:5678 usuario@IP` y abrir `http://localhost:5678`.
  - n8n: activar el usuario propietario o la autenticación, nunca dejarlo sin login.

### DOCKER_API_EXPUESTA
- Puerto 2375 abierto: es **control total del servidor** para cualquiera. Hay que cerrarlo ya:
  1. Quitar `-H tcp://0.0.0.0:2375` del servicio de Docker (`/etc/docker/daemon.json` o el override de systemd).
  2. Reiniciar Docker.
  3. Revisar si hay contenedores que no reconoce, porque es probable que ya lo hayan usado.

### BD_ESCUCHA_PUBLICA / PANEL_ESCUCHA_PUBLICA (baja)
- Hoy el firewall lo bloquea. Mejora recomendada: escuchar solo en 127.0.0.1. Así no depende de que el firewall siga activo.

### DOCKER_SOCKET_MONTADO / DOCKER_PRIVILEGIADO / DOCKER_MONTA_SISTEMA
- Si una app normal (la tienda, una API) tiene `/var/run/docker.sock`, `privileged: true` o monta `/`, `/etc` o `/root`, una falla en esa app se convierte en control total del servidor.
- Quitarlo del compose salvo que sea una herramienta de administración que lo necesita (Portainer, Traefik, Coolify, Watchtower).

---

## Acceso

### SSH_ROOT_CON_PASSWORD / SSH_CON_PASSWORD
- **Riesgo:** fuerza bruta. Hay servidores que reciben más de 10.000 intentos al día; el inventario muestra cuántos llegaron en las últimas 24 horas.
- **Arreglo, en este orden para no quedar fuera:**
  1. Confirmar que el alumno **ya entra con llave**. Si no:
     - En su computadora: `ssh-keygen -t ed25519`.
     - Luego: `ssh-copy-id usuario@IP`.
     - Probar `ssh usuario@IP`: debe entrar sin pedir contraseña.
  2. Recomendado: crear un usuario normal con sudo (`adduser deploy && usermod -aG sudo deploy`) y copiarle la llave.
  3. Crear `/etc/ssh/sshd_config.d/00-seguridad.conf` con:
     ```
     PasswordAuthentication no
     KbdInteractiveAuthentication no
     PermitRootLogin prohibit-password
     ```
     Va con el prefijo `00-` porque en sshd gana la primera vez que aparece una opción, y en Ubuntu suele haber un `50-cloud-init.conf` que vuelve a activar las contraseñas.
  4. `sudo sshd -t`, y si no hay errores, `sudo systemctl reload ssh`.
  5. **Sin cerrar la sesión actual**, abrir otra terminal y comprobar que se puede entrar.
- `instrucciones_ia`: "Verifica primero que mi usuario actual entra con llave SSH (revisa ~/.ssh/authorized_keys y pregúntame). Luego crea /etc/ssh/sshd_config.d/00-seguridad.conf con PasswordAuthentication no, KbdInteractiveAuthentication no y PermitRootLogin prohibit-password; valida con 'sshd -t' y recarga con 'systemctl reload ssh'. No cierres esta sesión: pídeme que pruebe entrar en una terminal nueva antes de terminar."

### SSH_ROOT (baja)
- Entrar como root con llave es aceptable. Lo ideal es un usuario normal con sudo y `PermitRootLogin no`.

### SIN_FAIL2BAN
- Instalar: `sudo apt install -y fail2ban`. En Ubuntu ya protege SSH al instalarlo.
- Revisar con `sudo fail2ban-client status sshd`.

### USUARIO_SIN_PASSWORD
- Ponerle contraseña (`sudo passwd usuario`) o bloquearlo (`sudo passwd -l usuario`) si no se usa.

---

## Firewall

### FIREWALL_INACTIVO
- **Arreglo con ufw, en este orden; si se invierten los pasos, el alumno queda fuera:**
  ```
  sudo ufw default deny incoming
  sudo ufw default allow outgoing
  sudo ufw allow OpenSSH        # o: sudo ufw allow <puerto-ssh>/tcp si cambiaste el puerto
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp
  sudo ufw enable
  ```
- Recordar que ufw **no** bloquea los puertos publicados por Docker (ver DOCKER_BD_PUBLICA).
- Lo ideal es también el firewall del proveedor (Hetzner Cloud Firewall, DigitalOcean Cloud Firewalls, AWS Security Groups), dejando abiertos solo 22, 80 y 443. Ese sí bloquea Docker, porque está fuera del servidor.

---

## Mantenimiento

### PARCHES_PENDIENTES / REINICIO_PENDIENTE
1. `sudo apt update && sudo apt upgrade -y`.
2. Reiniciar en un horario tranquilo (`sudo reboot`) si existe `/var/run/reboot-required`.
3. Antes de reiniciar, confirmar que las apps arrancan solas: `restart: unless-stopped` en Docker, `pm2 startup && pm2 save` en PM2, o un servicio de systemd habilitado.

### SIN_ACTUALIZACIONES_AUTO
- `sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades`.

### SO_SIN_SOPORTE
- Sin parches nunca más. Lo recomendable es un VPS nuevo con Ubuntu 24.04 LTS y migrar. Actualizar de versión en el mismo servidor es posible, pero arriesgado para un principiante.

### DISCO_LLENO
- Ver qué ocupa: `sudo du -xh / --max-depth=2 | sort -h | tail -20`.
- Limpiar Docker: `docker system prune` (borra imágenes y contenedores parados; avisar antes).
- Limpiar los logs: `sudo journalctl --vacuum-size=200M`.

---

## Archivos y web

### ENV_LEGIBLE
- `chmod 600 /ruta/.env` y que el dueño sea el usuario que corre la app (`chown deploy:deploy /ruta/.env`).

### NGINX_SIRVE_OCULTOS
- La carpeta pública de nginx (`root`) contiene `.env` o `.git`, y nadie bloquea los archivos ocultos.
- **Arreglo:**
  1. Que `root` apunte solo a la carpeta pública del build (`/public`, `/dist`), no a la raíz del proyecto.
  2. Además, agregar en cada `server {}`:
     ```
     location ~ /\.(?!well-known) { deny all; return 404; }
     ```
  3. `sudo nginx -t && sudo systemctl reload nginx`.
- Si el archivo ya estuvo expuesto, **rotar todas las llaves que tenía**.

### NGINX_VERSION
- `server_tokens off;` dentro de `http {}` en `/etc/nginx/nginx.conf`, y luego recargar nginx.

---

## Recuperación

### SIN_BACKUP
- **Mínimo indispensable:** un backup diario de la base de datos fuera del servidor. Si el VPS muere o lo hackean, el backup dentro del mismo VPS se pierde con él.
- **Opciones simples:**
  - Activar los backups o snapshots automáticos del proveedor: Hetzner cobra un 20% extra, DigitalOcean también los ofrece.
  - Hacer un `pg_dump` o `mysqldump` diario por cron y subirlo con `rclone` a Google Drive, S3 o Backblaze B2.
- **Y probar restaurar una vez.** Un backup que nunca se probó no es un backup.
- `instrucciones_ia`: "Crea un script /usr/local/bin/backup-db.sh que haga pg_dump (o mysqldump) de la base [nombre], lo comprima con fecha en /var/backups/db, borre los de más de 14 días y lo suba con rclone a [destino]. Prográmalo con cron a las 3 AM. No pongas contraseñas en el script: usa ~/.pgpass con permisos 600. Al final ejecútalo una vez y muéstrame que el archivo existe."

### CERTIFICADO_VENCIDO / CERTIFICADO_POR_VENCER
1. `sudo certbot renew --dry-run` para ver por qué falla. Lo más común: el puerto 80 cerrado o el DNS apuntando a otro lado.
2. Luego `sudo certbot renew`.
3. Revisar que el timer esté activo: `systemctl list-timers | grep certbot`.
