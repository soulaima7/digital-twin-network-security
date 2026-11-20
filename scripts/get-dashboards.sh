#!/usr/bin/env bash
# Telecharge le dashboard Grafana 1860 "Node Exporter Full" (cahier des charges 4.5)
# et le relie a la source de donnees provisionnee (uid "prometheus").
set -euo pipefail
OUT=monitoring/grafana/dashboards/node-exporter-full.json
if [ -s "$OUT" ]; then echo "[dashboards] $OUT deja present"; exit 0; fi
curl -fsSL https://grafana.com/api/dashboards/1860/revisions/latest/download -o "$OUT.tmp"
sed -e 's/\${DS_PROMETHEUS}/prometheus/g' -e 's/\${ds_prometheus}/prometheus/g' "$OUT.tmp" > "$OUT"
rm -f "$OUT.tmp"
echo "[dashboards] 1860 Node Exporter Full -> $OUT"
