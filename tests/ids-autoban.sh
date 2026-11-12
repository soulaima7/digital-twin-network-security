#!/usr/bin/env bash
# =====================================================================
#  Test Suricata + auto-ban (semaine 3) - scenario DURCI uniquement.
#  Usage : make deploy SCENARIO=hardened && ./tests/ids-autoban.sh
#
#  Deroule :
#   1. Lance un scan nmap de l'attaquant vers le web (declenche des alertes
#      ET SCAN / ET POLICY sur plusieurs ports en quelques secondes).
#   2. Attend jusqu'a 90s que l'auto-ban detecte >=5 alertes en 60s et
#      bannisse l'IP de l'attaquant (resultats/ban.log + set nftables).
#   3. Verifie que l'attaquant est bien bloque ensuite (forward -> drop).
# =====================================================================
set -u
P=clab-twin
ATTACKER_IP=10.10.30.10
WEB_IP=10.10.20.10

echo "=== 1) Verification : Suricata et auto-ban actifs sur fw ==="
if ! docker exec "$P-fw" pgrep -x suricata >/dev/null 2>&1; then
  echo "ECHEC : Suricata ne tourne pas sur fw (SCENARIO=hardened ? make deploy SCENARIO=hardened)"
  exit 1
fi
if ! docker exec "$P-fw" pgrep -f autoban.py >/dev/null 2>&1; then
  echo "ECHEC : ai/autoban.py ne tourne pas sur fw"
  exit 1
fi
echo "OK : suricata + autoban.py actifs"

echo
echo "=== 2) Scan nmap depuis l'attaquant (declenche les alertes) ==="
docker exec "$P-attacker" nmap -sS -T4 -p 1-2000 "$WEB_IP" >/tmp/nmap-ids-test.log 2>&1
tail -5 /tmp/nmap-ids-test.log

echo
echo "=== 3) Attente du bannissement (jusqu'a 90s) ==="
banned=0
for i in $(seq 1 18); do
  if docker exec "$P-fw" nft list set inet filter banned 2>/dev/null | grep -q "$ATTACKER_IP"; then
    banned=1
    break
  fi
  sleep 5
done

if [ "$banned" -eq 1 ]; then
  echo "OK : $ATTACKER_IP present dans le set nftables 'banned'"
else
  echo "ECHEC : $ATTACKER_IP n'a pas ete banni apres 90s"
  echo "--- dernieres alertes eve.json ---"
  docker exec "$P-fw" sh -c "tail -n 20 /var/log/suricata/eve.json" 2>/dev/null
  exit 1
fi

echo
echo "=== 4) results/ban.log ==="
docker exec "$P-fw" cat /results/ban.log 2>/dev/null | tail -5

echo
echo "=== 5) Verification : l'attaquant est maintenant bloque (ping) ==="
if docker exec "$P-attacker" ping -c1 -W2 "$WEB_IP" >/dev/null 2>&1; then
  echo "ATTENTION : ping encore accepte (verifier le set 'banned' et la regle 'ip saddr @banned drop')"
else
  echo "OK : trafic de l'attaquant bloque apres bannissement"
fi

echo
echo "Test IDS/auto-ban termine."
