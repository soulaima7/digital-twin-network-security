#!/usr/bin/env bash
# =====================================================================
#  Tests de connectivite et de durcissement - a lancer apres "make deploy"
#  Usage : ./tests/connectivity.sh baseline|hardened
#  Phase 1 : matrice de flux entre zones.
#  Phase 2 : durcissement SSH (mot de passe vs cle) et nginx (TLS,
#            server_tokens), depuis le client (poste "utilisateur legitime").
# =====================================================================
SCENARIO=${1:-baseline}
P=clab-twin                      # prefixe des conteneurs Containerlab
pass=0; fail=0

check() {  # description  noeud  commande  resultat_attendu
  if docker exec "$P-$2" sh -c "$3" >/dev/null 2>&1; then r=OK; else r=BLOQUE; fi
  if [ "$r" = "$4" ]; then s="PASS"; pass=$((pass+1)); else s="FAIL"; fail=$((fail+1)); fi
  printf "%-45s %-7s (attendu %-7s) %s\n" "$1" "$r" "$4" "$s"
}

check_contains() {  # description  noeud  commande  motif  (PASS si le motif est present)
  out=$(docker exec "$P-$2" sh -c "$3" 2>/dev/null)
  if printf '%s' "$out" | grep -q -- "$4"; then s="PASS"; pass=$((pass+1)); else s="FAIL"; fail=$((fail+1)); fi
  printf "%-45s %s (motif attendu : %s)\n" "$1" "$s" "$4"
}

check_not_contains() {  # description  noeud  commande  motif  (PASS si le motif est ABSENT)
  out=$(docker exec "$P-$2" sh -c "$3" 2>/dev/null)
  if printf '%s' "$out" | grep -q -- "$4"; then s="FAIL"; fail=$((fail+1)); else s="PASS"; pass=$((pass+1)); fi
  printf "%-45s %s (motif interdit : %s)\n" "$1" "$s" "$4"
}

[ "$SCENARIO" = "baseline" ] && X=OK || X=BLOQUE
# TLS (443) : ferme en baseline (pas d'ecoute TLS), ouvert en durci
[ "$SCENARIO" = "baseline" ] && TLS=BLOQUE || TLS=OK
# SSH par mot de passe : fonctionne en baseline, refuse en durci
[ "$SCENARIO" = "baseline" ] && PASSAUTH=OK || PASSAUTH=BLOQUE
# SSH par cle (admin) : refuse en baseline (cle non autorisee a cet endroit), fonctionne en durci
[ "$SCENARIO" = "baseline" ] && KEYAUTH=BLOQUE || KEYAUTH=OK

echo "=== VLANs sur le switch ==="
docker exec $P-sw bridge vlan show
echo
echo "=== Matrice de flux - scenario $SCENARIO ==="
check "client  -> passerelle LAN (ping)"   client   "ping -c1 -W2 10.10.10.1"   OK
check "client  -> web (ping)"              client   "ping -c1 -W2 10.10.20.10"  OK
check "client  -> web (HTTP 80)"           client   "curl -s -m3 http://10.10.20.10" OK
check "attacker-> web (HTTP 80)"           attacker "curl -s -m3 http://10.10.20.10" OK
check "attacker-> web (SSH 22)"            attacker "nc -z -w3 10.10.20.10 22"  OK
check "attacker-> web (HTTPS 443)"         attacker "nc -z -w3 10.10.20.10 443" $TLS
check "attacker-> web (ping)"              attacker "ping -c1 -W2 10.10.20.10"  $X
check "attacker-> client (ping)"           attacker "ping -c1 -W2 10.10.10.10"  $X
check "web     -> client (ping)"           web      "ping -c1 -W2 10.10.10.10"  $X

echo
echo "=== Durcissement SSH (depuis client, utilisateur legitime) - scenario $SCENARIO ==="
check "SSH mot de passe (testuser/password123)" client \
  "sshpass -p password123 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o PubkeyAuthentication=no testuser@10.10.20.10 true" \
  "$PASSAUTH"
check "SSH cle admin (secrets/ssh/web_admin)"   client \
  "ssh -i /root/.ssh/web_admin -o StrictHostKeyChecking=no -o ConnectTimeout=3 -o PasswordAuthentication=no -o IdentitiesOnly=yes testuser@10.10.20.10 true" \
  "$KEYAUTH"

echo
echo "=== Durcissement nginx (server_tokens) - scenario $SCENARIO ==="
if [ "$SCENARIO" = "baseline" ]; then
  check_contains "en-tete Server: nginx AVEC version (defaut)" client \
    "curl -s -m3 -I http://10.10.20.10/" "nginx/"
else
  check_not_contains "en-tete Server: nginx SANS version (server_tokens off)" client \
    "curl -sk -m3 -I https://10.10.20.10/" "nginx/"
fi

echo
echo "=== Chemin client -> web (doit passer par 10.10.10.1) ==="
docker exec $P-client traceroute -n -w1 -q1 10.10.20.10
echo
echo "Resultat : $pass PASS / $fail FAIL"
[ $fail -eq 0 ]
