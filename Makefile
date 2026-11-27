# =====================================================================
#  Digital Twin - commandes principales
#    make build                      construire les images Docker
#    make prepare                    generer la cle SSH + le certificat TLS
#    make deploy SCENARIO=baseline   deployer le jumeau (ou hardened)
#    make test   SCENARIO=baseline   lancer les tests de connectivite
#    make test-ids                   verifier Suricata + auto-ban (durci)
#    make destroy                    detruire le jumeau
#  Semaine 5 (attaques + score) :
#    make attack  SCENARIO=...       rejouer nmap + hydra + ab sur le jumeau
#    make score   SCENARIO=...       calculer le score de securite /100
#    make compare                    tableau + graphique baseline vs durci
#    make run-all                    cycle complet des deux scenarios
#  Semaine 6 (IA) :
#    make ai-deps                    installer scikit-learn, etc. (hote)
#    make ai-collect                 figer le trafic normal pour l'entrainement
#    make ai-train                   entrainer l'Isolation Forest
#    make ai-score                   score d'anomalie -> Grafana
#    make ai-evaluate                matrice de confusion
#    make ai-advise                  generer results/suggestions.nft
#    make ai-explain                 explication en langage clair (Ollama, bonus)
# =====================================================================
SCENARIO ?= baseline
IMAGES   := fw sw web client attacker
export SCENARIO

.PHONY: build prepare deploy destroy redeploy test test-ids inspect graph \
        attack score compare run-all \
        ai-deps ai-collect ai-train ai-score ai-run ai-windows ai-evaluate \
        ai-advise ai-explain

build:
	@for i in $(IMAGES); do docker build -t twin/$$i images/$$i || exit 1; done

# Genere (si absents) la cle SSH admin et le certificat TLS auto-signe
# utilises par le scenario durci. Idempotent : safe a rappeler a chaque deploy.
prepare:
	./scripts/gen-secrets.sh

deploy: build prepare
	sudo -E containerlab deploy -t twin.clab.yml --reconfigure

destroy:
	sudo containerlab destroy -t twin.clab.yml --cleanup

redeploy: destroy deploy

test:
	./tests/connectivity.sh $(SCENARIO)

test-ids:
	./tests/ids-autoban.sh

inspect:
	sudo containerlab inspect -t twin.clab.yml

graph:
	sudo containerlab graph -t twin.clab.yml

# =====================================================================
#  Semaine 5 : suite d'attaques et score de securite
# =====================================================================
# Rejoue nmap + hydra + ab contre 10.10.20.10 depuis l'attaquant. Les deux
# scenarios utilisent les MEMES attaques (c'est tout l'interet du avant/apres).
# Les sorties brutes sont ecrites dans results/ (monte sur l'attaquant).
attack:
	@docker exec -e SCENARIO=$(SCENARIO) clab-twin-attacker \
	  /opt/attack.sh $(SCENARIO) /opt/wordlist.txt

# Extrait les metriques et calcule le score /100 pour le scenario courant.
score:
	python3 analysis/score.py $(SCENARIO)

# Agrege les deux scores en un tableau + un graphique en barres.
compare:
	python3 analysis/compare.py

# Cycle complet (cahier des charges 4.6) : baseline attaque + score, puis
# durci attaque + score, puis comparaison. ~ quelques minutes.
run-all:
	-$(MAKE) destroy
	$(MAKE) deploy SCENARIO=baseline
	$(MAKE) attack SCENARIO=baseline
	$(MAKE) score  SCENARIO=baseline
	$(MAKE) destroy
	$(MAKE) deploy SCENARIO=hardened
	@echo "[run-all] attente du chargement des regles Suricata (~35s)..."
	@sleep 35
	$(MAKE) attack SCENARIO=hardened
	$(MAKE) score  SCENARIO=hardened
	$(MAKE) compare

# =====================================================================
#  Semaine 6 : detection d'anomalies (Isolation Forest) + conseiller IA
# =====================================================================
# Dependances IA, sur l'HOTE uniquement (les conteneurs restent en stdlib).
ai-deps:
	pip install -r ai/requirements.txt

# Fige le trafic normal courant comme jeu d'entrainement. A lancer apres
# 20 a 30 min de jumeau durci SANS attaque (cahier des charges 4.7).
ai-collect:
	@test -s logs/eve.json || { echo "logs/eve.json vide : deployer en durci et laisser tourner le trafic normal"; exit 1; }
	@cp logs/eve.json logs/eve_normal.json
	@echo "logs/eve_normal.json <- instantane de logs/eve.json ($$(wc -l < logs/eve_normal.json) lignes)"

ai-train:
	python3 ai/anomaly.py train --eve logs/eve_normal.json

ai-score:
	python3 ai/anomaly.py score --eve logs/eve.json

ai-run:
	python3 ai/anomaly.py run --eve logs/eve.json --interval 60

# Construit results/attack_windows.json depuis les horodatages de attack.sh.
ai-windows:
	python3 analysis/attack_windows.py hardened

ai-evaluate: ai-windows
	python3 ai/anomaly.py evaluate --eve logs/eve.json \
	  --attacks results/attack_windows.json --plot

ai-advise:
	python3 ai/advisor.py --eve logs/eve.json

ai-explain:
	python3 ai/explain.py --eve logs/eve.json

include monitoring/monitoring.mk
