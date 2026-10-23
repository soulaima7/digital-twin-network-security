#!/bin/sh
prometheus-node-exporter --web.listen-address=:9100 >/dev/null 2>&1 &
exec sleep infinity
