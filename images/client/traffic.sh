#!/bin/sh
# =====================================================================
#  Generateur de trafic normal (poste utilisateur LAN)
#  - Navigation curl vers le serveur web DMZ, avec des pauses aleatoires
#    pour imiter un usage humain.
#  - Strictement identique dans les deux scenarios (baseline et durci) :
#    seul le comportement du reseau/firewall change, pas le trafic genere.
#  - -k ignore la verification du certificat auto-signe en scenario durci
#    (http://... est alors redirige en https://... par nginx).
#  - Ce trafic "propre" sert aussi, en semaine 6, a entrainer le modele
#    de detection d'anomalies (20 a 30 minutes de trafic normal).
# =====================================================================
TARGET="http://10.10.20.10/"
LOG="/var/log/traffic.log"

echo "[traffic.sh] demarrage - cible $TARGET" >> "$LOG" 2>/dev/null

while true; do
  ts="$(date '+%Y-%m-%dT%H:%M:%S')"
  code="$(curl -s -m 5 -L -k -o /dev/null -w '%{http_code}' "$TARGET" 2>/dev/null)"
  echo "$ts GET $TARGET -> ${code:-ERR}" >> "$LOG" 2>/dev/null

  # pause aleatoire entre 2 et 10 secondes (comportement humain, non robotique)
  pause="$(shuf -i 2-10 -n 1 2>/dev/null || echo 5)"
  sleep "$pause"
done
