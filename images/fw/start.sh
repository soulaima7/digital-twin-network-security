#!/bin/sh
# =====================================================================
#  Pare-feu central : node_exporter (toujours actif) + Suricata/auto-ban
#  (actifs uniquement en scenario durci - SCENARIO est injecte par
#  Containerlab via twin.clab.yml). nftables.conf est deja charge par
#  le bloc "exec:" de twin.clab.yml avant que ce script ne demarre.
# =====================================================================
prometheus-node-exporter --web.listen-address=:9100 >/dev/null 2>&1 &

if [ "$SCENARIO" = "hardened" ]; then
  echo "[fw] scenario durci : demarrage de Suricata (IDS) et de l'auto-ban"

  # suricata.yaml et le set de regles ET Open sont deja dans l'image/mount ;
  # -D demonise Suricata en arriere-plan.
  suricata -c /etc/suricata/suricata.yaml --af-packet -k none -D

  # Attend que Suricata ait cree eve.json avant de lancer l'auto-ban (30s max)
  i=0
  while [ ! -f /var/log/suricata/eve.json ] && [ "$i" -lt 30 ]; do
    sleep 1
    i=$((i + 1))
  done

  python3 /opt/ai/autoban.py >> /var/log/autoban.log 2>&1 &
else
  echo "[fw] scenario baseline : aucune detection, aucun auto-ban (volontaire)"
fi

exec sleep infinity
