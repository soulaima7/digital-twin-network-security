#!/bin/sh
prometheus-node-exporter --web.listen-address=:9100 >/dev/null 2>&1 &
/usr/local/bin/traffic.sh &
exec sleep infinity
