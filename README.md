# Digital Twin for Network Security — Phase 2

Jumeau numérique du réseau d'une entreprise, décrit entièrement en code (Containerlab + Docker).
Projet fédérateur Réseau & Sécurité — MP1 ASRI 2026–2027 — Soulaima Hssine, Oumaima Bouali.

Phase 1 (semaine 1) a livré la topologie réseau (VLANs, adressage, routage, pare-feu nftables).
**Phase 2** ajoute les semaines 2 et 3 du planning :

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
