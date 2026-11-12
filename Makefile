# =====================================================================
#  Digital Twin - commandes principales
#    make build                      construire les images Docker
#    make prepare                    generer la cle SSH + le certificat TLS
#    make deploy SCENARIO=baseline   deployer le jumeau (ou hardened)
#    make test   SCENARIO=baseline   lancer les tests de connectivite
#    make test-ids                   verifier Suricata + auto-ban (durci)
#    make destroy                    detruire le jumeau
# =====================================================================
SCENARIO ?= baseline
IMAGES   := fw sw web client attacker
export SCENARIO

.PHONY: build prepare deploy destroy redeploy test test-ids inspect graph attack

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

attack:
	@echo "Suite d'attaques : prevue en semaine 5"
