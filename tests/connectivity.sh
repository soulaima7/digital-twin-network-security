#!/usr/bin/env bash
# =====================================================================
#  Tests de connectivite Phase 1 - a lancer apres "make deploy"
#  Usage : ./tests/connectivity.sh baseline|hardened
# =====================================================================
SCENARIO=${1:-baseline}
P=clab-twin                      # prefixe des conteneurs Containerlab
pass=0; fail=0

check() {  # description  noeud  commande  resultat_attendu
  if docker exec "$P-$2" sh -c "$3" >/dev/null 2>&1; then r=OK; else r=BLOQUE; fi
  if [ "$r" = "$4" ]; then s="PASS"; pass=$((pass+1)); else s="FAIL"; fail=$((fail+1)); fi
  printf "%-40s %-7s (attendu %-7s) %s\n" "$1" "$r" "$4" "$s"
}

[ "$SCENARIO" = "baseline" ] && X=OK || X=BLOQUE

echo "=== VLANs sur le switch ==="
docker exec $P-sw bridge vlan show
echo
echo "=== Matrice de flux - scenario $SCENARIO ==="
check "client  -> passerelle LAN (ping)"   client   "ping -c1 -W2 10.10.10.1"   OK
check "client  -> web (ping)"              client   "ping -c1 -W2 10.10.20.10"  OK
check "client  -> web (HTTP 80)"           client   "curl -s -m3 http://10.10.20.10" OK
check "attacker-> web (HTTP 80)"           attacker "curl -s -m3 http://10.10.20.10" OK
check "attacker-> web (SSH 22)"            attacker "nc -z -w3 10.10.20.10 22"  OK
check "attacker-> web (ping)"              attacker "ping -c1 -W2 10.10.20.10"  $X
check "attacker-> client (ping)"           attacker "ping -c1 -W2 10.10.10.10"  $X
check "web     -> client (ping)"           web      "ping -c1 -W2 10.10.10.10"  $X
echo
echo "=== Chemin client -> web (doit passer par 10.10.10.1) ==="
docker exec $P-client traceroute -n -w1 -q1 10.10.20.10
echo
echo "Resultat : $pass PASS / $fail FAIL"
[ $fail -eq 0 ]
