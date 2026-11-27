# Digital Twin for Network Security

Jumeau numérique du réseau d'une entreprise, décrit entièrement en code (Containerlab + Docker).
Projet fédérateur Réseau & Sécurité — MP1 ASRI 2026–2027 — Soulaima Hssine, Oumaima Bouali.

- **Phase 1** (semaine 1) — topologie réseau : VLANs, adressage, routage, pare-feu nftables.
- **Phase 2** (semaines 2–3) — durcissement SSH/nginx, générateur de trafic, Suricata + auto-ban.
- **Phase 3** (semaine 4) — supervision Prometheus/Grafana + alertes Telegram (voir `monitoring/`).
- **Phase 4** (semaines 5–6) — suite d'attaques + score de sécurité, puis brique IA (détection
  d'anomalies Isolation Forest, matrice de confusion, conseiller de règles).

Détail des semaines 2–3 :

- **Semaine 2** — durcissement des services : SSH (mot de passe faible en baseline / clé uniquement
  en durci) et nginx (configuration par défaut en baseline / `server_tokens off` + TLS auto-signé
  en durci), et un générateur de trafic normal (`traffic.sh`) sur le client.
- **Semaine 3** — détection d'intrusion et auto-ban : Suricata (règles ET Open) sur le pare-feu,
  et `ai/autoban.py` qui bannit automatiquement, via nftables, toute source déclenchant
  5 alertes en 60 secondes (scénario durci uniquement).

## Architecture

```
                     +-----------------------------+
                     |  fw  (nftables, routeur,    |
                     |  Suricata + auto-ban durci) |
                     |  eth1.10 10.10.10.1  VLAN10 |
                     |  eth1.20 10.10.20.1  VLAN20 |
                     |  eth2    10.10.30.1  WAN    |
                     +------+---------------+------+
                     eth1   | trunk 802.1Q  | eth2
                            |               |
                    +-------+------+   +----+---------+
                    | sw (VLAN 10, |   | attacker     |
                    |     VLAN 20) |   | 10.10.30.10  |
                    +--+--------+--+   | zone ATK     |
                 eth2  |        | eth3 +--------------+
            (VLAN 10)  |        |  (VLAN 20)
              +--------+--+  +--+-----------------+
              | client    |  | web                |
              | 10.10.10.10| | 10.10.20.10        |
              | traffic.sh|  | nginx + sshd       |
              | zone LAN  |  | zone DMZ           |
              +-----------+  +--------------------+

  Réseau de gestion 172.20.20.0/24 (eth0 de chaque nœud) : supervision uniquement.
```

| Nœud | Rôle | Zone / VLAN | IP plan de données | IP gestion |
|---|---|---|---|---|
| fw | Pare-feu nftables + routeur inter-VLAN + Suricata/auto-ban (durci) | Centre | 10.10.10.1 / 10.10.20.1 / 10.10.30.1 | 172.20.20.2 |
| sw | Switch L2 (bridge Linux VLAN-aware) | — | — | 172.20.20.6 |
| web | nginx + SSH (durcissement scénario) | DMZ / VLAN 20 | 10.10.20.10/24 | 172.20.20.3 |
| client | Poste utilisateur, génère du trafic normal | LAN / VLAN 10 | 10.10.10.10/24 | 172.20.20.4 |
| attacker | nmap, hydra, ab | ATK (WAN) | 10.10.30.10/24 | 172.20.20.5 |

## Durcissement SSH / nginx (semaine 2)

| Élément | Baseline | Durci |
|---|---|---|
| SSH (web) | Mot de passe, compte faible `testuser` / `password123` | Clé uniquement : `PasswordAuthentication no`, `PermitRootLogin no`, `MaxAuthTries 3` |
| nginx (web) | Paramètres par défaut (port 80, version visible) | `server_tokens off` ; HTTPS 443 avec certificat TLS auto-signé ; HTTP redirige vers HTTPS |
| Client | `traffic.sh` : navigation curl avec pauses aléatoires (2 à 10 s) | Identique |

La clé SSH admin et le certificat TLS sont générés localement (jamais commités) par
`scripts/gen-secrets.sh`, appelé automatiquement par `make deploy` (cible `prepare`).

## Détection d'intrusion et auto-ban (semaine 3, scénario durci uniquement)

- Suricata tourne sur `fw`, capture en af-packet sur `eth1.10`, `eth1.20`, `eth2`, journalise
  les alertes et les flux dans `logs/eve.json` (monté sur l'hôte).
- `ai/autoban.py` surveille `eve.json` : si une IP source déclenche **5 alertes en 60 s**, elle est
  ajoutée au set nftables `banned` pour **15 minutes**, avec une ligne dans `results/ban.log`.
- Le client LAN (`10.10.10.10`) est en liste de confiance et n'est jamais banni.
- En scénario **baseline**, ni Suricata ni l'auto-ban ne sont lancés (volontairement : aucune
  détection, cohérent avec « réseau plat, aucun filtrage »).

## Suite d'attaques et score de sécurité (semaine 5)

Le script `/opt/attack.sh` (image attaquant) rejoue les **mêmes** attaques sur les deux
scénarios, toujours contre `10.10.20.10` : scan `nmap -sS -T4 -p 1-10000`, brute force SSH
`hydra -t 4` (wordlist courte contenant `password123`), surcharge HTTP `ab -n 5000 -c 50`.

`analysis/score.py` extrait les métriques (ports exposés, succès du brute force, temps de
détection Suricata, temps de bannissement, disponibilité) et calcule un **score /100** :
on part de 100 et on retire 30 (brute force réussi), 20 (plus de 3 ports exposés), 20
(aucune alerte en 30 s), 20 (attaquant jamais banni), 10 (disponibilité < 90 %).
`analysis/compare.py` produit le tableau et le graphique en barres baseline vs durci.

```bash
make run-all            # cycle complet : baseline + durci, attaques, scores, comparaison
# ou pas a pas :
make deploy SCENARIO=baseline && make attack SCENARIO=baseline && make score SCENARIO=baseline
make destroy && make deploy SCENARIO=hardened
make attack SCENARIO=hardened && make score SCENARIO=hardened && make compare
```

Résultat type : **baseline 30/100** (brute force réussi, aucune détection, jamais banni) vs
**durci 90/100** (détecté en quelques secondes, attaquant banni ; les requêtes `ab` de
l'attaquant échouent justement *parce qu'*il est banni).

## Brique IA : détection d'anomalies et conseiller de règles (semaine 6)

`ai/anomaly.py` découpe `eve.json` en fenêtres d'1 minute (caractéristiques : nombre
d'alertes, ports de destination uniques, signatures uniques, nombre de flux, octets) et
entraîne un **Isolation Forest** (`contamination=0.05`) sur 20–30 min de trafic normal.
Chaque fenêtre reçoit un score d'anomalie entre 0 et 1, écrit dans `results/anomaly_score`,
lu par `ai/exporter.py` et publié dans Grafana (panneau + alerte > 0.7 déjà en place).

```bash
make ai-deps            # scikit-learn, numpy, matplotlib, joblib (hote uniquement)
# 1) entrainement sur du trafic normal (jumeau durci, SANS attaque, 20-30 min)
make ai-collect         # fige logs/eve.json -> logs/eve_normal.json
make ai-train
# 2) en exploitation (pendant/apres une attaque)
make ai-score           # score de la derniere fenetre -> Grafana
make ai-evaluate        # matrice de confusion (fenetres d'attaque connues)
make ai-advise          # regroupe les alertes anormales -> results/suggestions.nft
make ai-explain         # explication en langage clair (Ollama llama3.2:3b, bonus)
```

Boucle « l'IA propose, le jumeau valide » : `ai/advisor.py` regroupe les alertes des
fenêtres anormales par IP source et port de destination et génère `results/suggestions.nft`
(règles nftables persistantes). Un humain les **lit**, les applique dans le jumeau durci,
rejoue l'attaque et vérifie que le score s'améliore — rien n'est appliqué automatiquement.

## Arborescence

```
twin.clab.yml             topologie complète (nœuds, liens, VLANs, IPs, routes, binds)
Makefile                  build / prepare / deploy / test / test-ids / destroy
images/<noeud>/           Dockerfile + scripts de chaque nœud (debian:12-slim)
configs/baseline/         nftables, sshd_config, nginx.conf : tout faible
configs/hardened/         nftables, sshd_config, nginx.conf : tout durci
configs/suricata/         suricata.yaml (identique aux deux scénarios)
secrets/                  clé SSH admin + certificat TLS générés (non versionnés)
ai/autoban.py             détection 5 alertes/60s → ban nftables 15 min
ai/exporter.py            exporter Prometheus du jumeau (:9200)
ai/anomaly.py             détection d'anomalies Isolation Forest (train/score/run/evaluate)
ai/advisor.py             conseiller de règles → results/suggestions.nft
ai/explain.py             explication des anomalies via Ollama (bonus)
ai/requirements.txt       dépendances IA (hôte uniquement)
analysis/score.py         extraction des métriques + score /100 par scénario
analysis/compare.py       tableau + graphique baseline vs durci
analysis/attack_windows.py intervalles d'attaque (étiquetage de la matrice de confusion)
images/attacker/attack.sh suite d'attaques nmap + hydra + ab (semaine 5)
scripts/setup-host.sh     installation de Docker + Containerlab
scripts/gen-secrets.sh    génère la clé SSH et le certificat TLS (idempotent)
tests/connectivity.sh     matrice de flux + durcissement SSH/nginx (PASS/FAIL)
tests/ids-autoban.sh      scan nmap → vérifie alerte + bannissement
docs/architecture.drawio  schéma Draw.io
```

## Démarrage rapide (Ubuntu 24.04)

```bash
git clone <url-du-depot> twin && cd twin
./scripts/setup-host.sh          # une seule fois, puis se reconnecter
make deploy SCENARIO=baseline    # build + genere les secrets + deploie
make test   SCENARIO=baseline
make destroy
make deploy SCENARIO=hardened
make test   SCENARIO=hardened
make test-ids                    # Suricata + auto-ban (scenario durci uniquement)
```

Accès à un nœud : `docker exec -it clab-twin-client bash`

## Résultats attendus des tests

| Flux / test | Baseline | Durci |
|---|---|---|
| client → web (ping, HTTP) | OK | OK |
| attacker → web HTTP 80 / SSH 22 | OK | OK |
| attacker → web HTTPS 443 | BLOQUÉ (pas d'écoute TLS) | OK |
| attacker → web ping | OK | BLOQUÉ |
| attacker → client | OK | BLOQUÉ |
| web → client (DMZ → LAN) | OK | BLOQUÉ |
| SSH mot de passe (client → web) | OK | BLOQUÉ |
| SSH clé admin (client → web) | BLOQUÉ | OK |
| En-tête `Server: nginx/<version>` | présent | absent (`server_tokens off`) |
| Scan nmap attaquant → bannissement | — (pas de Suricata) | banni en ≤ 60 s (`test-ids`) |

## Dépannage

- `Unknown device type` sur `eth1.10` → `sudo modprobe 8021q`
- Image introuvable → `make build`
- Un ancien lab gêne → `make destroy` puis `docker ps -a`
- Ne jamais attaquer une IP 172.20.20.x : ce réseau contourne le pare-feu.
- `make prepare` échoue → vérifier que `ssh-keygen` et `openssl` sont installés sur l'hôte
  (fournis par `scripts/setup-host.sh` / paquet `openssh-client`).
- Suricata ne démarre pas / 0 alerte → vérifier `SCENARIO=hardened` et que la construction de
  l'image `fw` a bien pu joindre `rules.emergingthreats.net` (accès Internet requis au build).
