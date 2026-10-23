#!/bin/sh
prometheus-node-exporter --web.listen-address=:9100 >/dev/null 2>&1 &
/usr/sbin/sshd
nginx
exec sleep infinity
