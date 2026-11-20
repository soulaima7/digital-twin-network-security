#!/usr/bin/env bash
# =====================================================================
#  tests/ids-autoban.sh - Test IDS + auto-ban (scenario durci)
#  Usage : make test-ids   (apres make deploy SCENARIO=hardened)
#
#  1) Suricata et autoban.py tournent sur fw
#  2) Attente que Suricata ait charge les regles ET Open (sinon 0 alerte)
#  3) Etat initial propre (attaquant retire du set banned s'il y est)
#  4) Scan nmap depuis l'attaquant, borne dans le temps
#  5) Attente du bannissement (jusqu'a 90 s)
#  6) Bilan : alertes de CE scan, ban.log, doublons ignores
#  7) Verification : l'attaquant est bloque (ping + HTTP)
# =====================================================================
set -u
FW=clab-twin-fw
ATK=clab-twin-attacker
ATK_IP=10.10.30.10
WEB_IP=10.10.20.10
EVE=/var/log/suricata/eve.json
SURI_LOG=/var/log/suricata/suricata.log
READY_MAX=150      # s : attente max du chargement des regles
BAN_MAX=90         # s : attente max du bannissement

fail() { echo "ECHEC : $*"; exit 1; }
alerts() { local n; n=$(docker exec "$FW" grep -c '"event_type":"alert"' "$EVE" 2>/dev/null); echo "${n:-0}"; }
banned() { docker exec "$FW" nft list set inet filter banned 2>/dev/null | grep -q "$ATK_IP"; }

echo "=== 1) Verification : Suricata et auto-ban actifs sur fw ==="
scenario=$(docker exec "$FW" printenv SCENARIO 2>/dev/null)
[ "$scenario" = "hardened" ] || fail "scenario '$scenario' deploye (make deploy SCENARIO=hardened)"
docker exec "$FW" pgrep -f suricata >/dev/null || fail "Suricata ne tourne pas sur fw"
docker exec "$FW" pgrep -f autoban.py >/dev/null || fail "autoban.py ne tourne pas sur fw"
echo "OK : suricata + autoban.py actifs"

echo
echo "=== 2) Attente du chargement des regles Suricata (max ${READY_MAX}s) ==="
# Suricata ecrit "Engine started" quand les regles sont chargees. Si son
# journal n'existe pas, on se fie a l'age du processus (>= 90 s).
ready=0
for i in $(seq 1 "$READY_MAX"); do
  # suricata.log est conserve entre deploiements (dossier logs/) : on ne compte
  # que le "Engine started" ecrit APRES la derniere banniere de demarrage.
  if docker exec "$FW" awk '/This is Suricata version/{s=NR} tolower($0)~/engine started/{e=NR} END{exit !(s>0 && e>s)}' "$SURI_LOG" 2>/dev/null; then
    echo "OK : Suricata pret (\"Engine started\" apres ${i}s d'attente)"; ready=1; break
  fi
  pid=$(docker exec "$FW" pgrep -of suricata 2>/dev/null)
  age=$(docker exec "$FW" ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
  if [ -n "$age" ] && [ "$age" -ge 90 ]; then
    echo "OK : Suricata demarre depuis ${age}s (journal sans \"Engine started\")"; ready=1; break
  fi
  sleep 1
done
[ "$ready" = 1 ] || fail "Suricata pas pret apres ${READY_MAX}s"

echo
echo "=== 3) Etat initial ==="
if banned; then
  docker exec "$FW" nft delete element inet filter banned "{ $ATK_IP }"
  echo "Attaquant deja banni : retire du set pour un test propre"
fi
before=$(alerts)
bans_before=$(wc -l < results/ban.log 2>/dev/null || echo 0)
echo "Alertes deja presentes dans eve.json : $before"

echo
echo "=== 4) Scan nmap depuis l'attaquant (declenche les alertes) ==="
# Options du cahier des charges (-sS -T4 -p 1-10000) + bornes de temps :
# apres le ban, toutes les sondes sont ignorees et nmap ralentirait sans fin.
start=$(date +%s)
docker exec "$ATK" timeout 120 nmap -sS -T4 --max-retries 1 --host-timeout 90s \
  -p 1-10000 "$WEB_IP" | grep -E "open|Nmap done|timed out"
echo "Duree du scan : $(( $(date +%s) - start ))s"

echo
echo "=== 5) Attente du bannissement (jusqu'a ${BAN_MAX}s) ==="
ok=0
for i in $(seq 1 "$BAN_MAX"); do
  if banned; then echo "OK : $ATK_IP present dans le set nftables 'banned' (${i}s apres le scan)"; ok=1; break; fi
  sleep 1
done

echo
echo "=== 6) Bilan ==="
after=$(alerts)
echo "Alertes Suricata generees par ce scan : $(( after - before )) (seuil d'auto-ban : 5)"
echo "--- nouvelles lignes de results/ban.log ---"
tail -n +"$(( bans_before + 1 ))" results/ban.log 2>/dev/null || echo "(aucune)"
dups=$(docker exec "$FW" grep -c "doublon ignore" /var/log/autoban.log 2>/dev/null); dups=${dups:-0}
echo "Doublons ignores par autoban.py (alerte vue sur 2 interfaces) : $dups"
if [ "$ok" != 1 ]; then
  echo "--- dernieres alertes eve.json ---"
  docker exec "$FW" grep '"event_type":"alert"' "$EVE" | tail -5
  fail "$ATK_IP n'a pas ete banni apres ${BAN_MAX}s"
fi

echo
echo "=== 7) Verification : l'attaquant est maintenant bloque ==="
if docker exec "$ATK" ping -c 2 -W 1 "$WEB_IP" >/dev/null 2>&1; then
  fail "l'attaquant joint encore le web en ICMP"
fi
if docker exec "$ATK" curl -s -m 3 -o /dev/null "http://$WEB_IP/"; then
  fail "l'attaquant joint encore le web en HTTP (port 80 publie, devrait etre bloque par le ban)"
fi
echo "OK : trafic de l'attaquant bloque apres bannissement (ICMP et HTTP)"
echo
echo "RESULTAT : test IDS / auto-ban REUSSI"
