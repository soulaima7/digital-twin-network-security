# Supervision (semaine 4) - inclus par le Makefile principal :
#     include monitoring/monitoring.mk
# make monitor-up   : Prometheus :9090 + Grafana :3000 + exporter Python :9200
# make monitor-down : arrete les trois
# make monitor-check: verifie que tout repond

EXPORTER_PID := results/exporter.pid

.PHONY: monitor-up monitor-down monitor-check monitor-config

monitor-config:
	@test -f monitoring/.env || { echo "ERREUR : copier monitoring/.env.example en monitoring/.env et le remplir"; exit 1; }
	@set -a; . monitoring/.env; set +a; python3 monitoring/render-contactpoints.py \
	  monitoring/grafana/provisioning/alerting/contactpoints.yml.tmpl \
	  monitoring/grafana/provisioning/alerting/contactpoints.yml
	@bash scripts/get-dashboards.sh

monitor-up: monitor-config
	@mkdir -p results logs
	@sudo chmod -R o+rX logs results 2>/dev/null || true
	@if [ -f $(EXPORTER_PID) ] && kill -0 $$(cat $(EXPORTER_PID)) 2>/dev/null; then \
	  echo "[exporter] deja lance (pid $$(cat $(EXPORTER_PID)))"; \
	else \
	  nohup python3 ai/exporter.py > results/exporter.log 2>&1 & echo $$! > $(EXPORTER_PID); \
	  echo "[exporter] lance sur :9200 (log : results/exporter.log)"; \
	fi
	docker compose -f monitoring/docker-compose.yml up -d
	@echo "Grafana    : http://localhost:3000  (admin / mot de passe de monitoring/.env)"
	@echo "Prometheus : http://localhost:9090/targets"

monitor-down:
	-docker compose -f monitoring/docker-compose.yml down
	@if [ -f $(EXPORTER_PID) ]; then kill $$(cat $(EXPORTER_PID)) 2>/dev/null || true; rm -f $(EXPORTER_PID); echo "[exporter] arrete"; fi

monitor-check:
	@echo "== exporter :9200";   curl -s localhost:9200/metrics | grep -E '^twin_(web_up|banned_ips|suricata_alerts_per_minute|scenario_info|eve_readable)' || echo "ECHEC exporter"
	@echo "== cibles Prometheus"; python3 monitoring/check-targets.py
	@echo "== Grafana";           curl -s localhost:3000/api/health || echo "ECHEC Grafana"
