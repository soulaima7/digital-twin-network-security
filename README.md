# Digital Twin for Network Security — Phase 1

Jumeau numérique du réseau d'une entreprise, décrit entièrement en code (Containerlab + Docker).
Projet fédérateur Réseau & Sécurité — MP1 ASRI 2026–2027 — Soulaima Hssine, Oumaima Bouali.

## Architecture

```
                     +-----------------------------+
                     |  fw  (nftables, routeur)    |
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
              +--------+--+  +--+-----------+
              | client    |  | web          |
              | 10.10.10.10| | 10.10.20.10  |
              | zone LAN  |  | zone DMZ     |
              +-----------+  +--------------+

  Réseau de gestion 172.20.20.0/24 (eth0 de chaque nœud) : supervision uniquement.
```

| Nœud | Rôle | Zone / VLAN | IP plan de données | IP gestion |
|---|---|---|---|---|
| fw | Pare-feu nftables + routeur inter-VLAN | Centre | 10.10.10.1 / 10.10.20.1 / 10.10.30.1 | 172.20.20.2 |
| sw | Switch L2 (bridge Linux VLAN-aware) | — | — | 172.20.20.6 |
| web | nginx + SSH | DMZ / VLAN 20 | 10.10.20.10/24 | 172.20.20.3 |
| client | Poste utilisateur | LAN / VLAN 10 | 10.10.10.10/24 | 172.20.20.4 |
| attacker | nmap, hydra, ab | ATK (WAN) | 10.10.30.10/24 | 172.20.20.5 |

## Arborescence

```
twin.clab.yml            topologie complète (nœuds, liens, VLANs, IPs, routes)
Makefile                 build / deploy / test / destroy
images/<noeud>/          Dockerfile de chaque nœud (debian:12-slim)
configs/baseline/        nftables : tout autorisé
configs/hardened/        nftables : deny all par défaut
scripts/setup-host.sh    installation de Docker + Containerlab
tests/connectivity.sh    matrice de flux PASS/FAIL
docs/architecture.drawio schéma Draw.io
```

## Démarrage rapide (Ubuntu 24.04)

```bash
git clone <url-du-depot> twin && cd twin
./scripts/setup-host.sh          # une seule fois, puis se reconnecter
make deploy SCENARIO=baseline
make test   SCENARIO=baseline
make destroy
make deploy SCENARIO=hardened
make test   SCENARIO=hardened
```

Accès à un nœud : `docker exec -it clab-twin-client bash`

## Résultats attendus des tests

| Flux | Baseline | Durci |
|---|---|---|
| client → web (ping, HTTP) | OK | OK |
| attacker → web HTTP 80 / SSH 22 | OK | OK |
| attacker → web ping | OK | BLOQUÉ |
| attacker → client | OK | BLOQUÉ |
| web → client (DMZ → LAN) | OK | BLOQUÉ |

## Dépannage

- `Unknown device type` sur `eth1.10` → `sudo modprobe 8021q`
- Image introuvable → `make build`
- Un ancien lab gêne → `make destroy` puis `docker ps -a`
- Ne jamais attaquer une IP 172.20.20.x : ce réseau contourne le pare-feu.
