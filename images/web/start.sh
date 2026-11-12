#!/bin/sh
# sshd et nginx lisent leurs chemins de configuration par defaut
# (/etc/ssh/sshd_config, /etc/nginx/nginx.conf) : c'est le bind Containerlab
# configs/${SCENARIO}/... qui decide du comportement baseline/durci.
prometheus-node-exporter --web.listen-address=:9100 >/dev/null 2>&1 &

# Regenere les cles d'hote SSH si l'image/volume ne les a pas encore (idempotent)
ssh-keygen -A >/dev/null 2>&1

/usr/sbin/sshd
nginx
exec sleep infinity
