# Supervision du jumeau (semaine 4)

Prometheus (:9090) + Grafana (:3000) en Docker Compose sur l'hôte (`network_mode: host`),
et l'exporter Python `ai/exporter.py` (:9200), conformément au cahier des charges §4.5.

```
node_exporter fw/web/client (172.20.20.x:9100) ─┐
ai/exporter.py (localhost:9200) ────────────────┼─> Prometheus :9090 ─> Grafana :3000 ─> Telegram
  ├─ logs/eve.json          (alertes Suricata)  ┘
  ├─ nft list set banned    (IP bannies)
  ├─ curl client -> web     (disponibilité, à travers fw)
  └─ results/anomaly_score  (IA, semaine 6)
```

## Mise en place (une seule fois)

1. Créer le bot Telegram : dans Telegram, ouvrir **@BotFather**, envoyer `/newbot`, copier le token.
2. Envoyer un message quelconque au nouveau bot, puis ouvrir
   `https://api.telegram.org/bot<TOKEN>/getUpdates` et relever `"chat":{"id": ...}`.
3. `cp monitoring/.env.example monitoring/.env` puis remplir le token, le chat id et le mot de passe Grafana.
4. Ajouter à la fin du `Makefile` : `include monitoring/monitoring.mk`
5. Ajouter `gitignore-additions.txt` à la fin de `.gitignore` (le token ne doit jamais être commité).

## Utilisation

```bash
make deploy SCENARIO=hardened   # le jumeau d'abord
make monitor-up                 # exporter + Prometheus + Grafana
make monitor-check              # tout doit être "up"
make monitor-down
```

- Grafana : http://localhost:3000 (admin / mot de passe de `.env`), tableau de bord **Twin security** en page d'accueil, **Node Exporter Full** (1860) dans le dossier Twin.
- Prometheus : http://localhost:9090/targets

## Alertes Telegram (3 conditions du cahier des charges)

| Alerte | Condition | Délai |
| --- | --- | --- |
| Site web indisponible | `twin_web_up < 1` | 1 min |
| IP bannie | `increase(twin_bans_total[1m]) > 0` | immédiat |
| Score d'anomalie élevé | `twin_anomaly_score > 0.7` (quand le modèle est prêt) | immédiat |

## Métriques de l'exporter

| Métrique | Sens |
| --- | --- |
| `twin_suricata_alerts_per_minute` | alertes Suricata des 60 dernières secondes |
| `twin_suricata_alerts_by_src_total{src_ip}` | alertes par IP source |
| `twin_banned_ips` | IP actuellement dans le set nftables `banned` |
| `twin_bans_total` | lignes BAN dans `results/ban.log` |
| `twin_web_up`, `twin_web_response_seconds` | site vu depuis le client, à travers fw |
| `twin_anomaly_score`, `twin_anomaly_model_ready` | score IA (semaine 6) |
| `twin_scenario_info{scenario}` | scénario déployé |
| `twin_eve_readable` | 0 = l'exporter ne peut pas lire `logs/eve.json` (droits) |
