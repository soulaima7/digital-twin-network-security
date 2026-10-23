# =====================================================================
#  Digital Twin - commandes principales
#    make build                      construire les images Docker
#    make deploy SCENARIO=baseline   deployer le jumeau (ou hardened)
#    make test   SCENARIO=baseline   lancer les tests de connectivite
#    make destroy                    detruire le jumeau
# =====================================================================
SCENARIO ?= baseline
IMAGES   := fw sw web client attacker
export SCENARIO

.PHONY: build deploy destroy redeploy test inspect graph attack

build:
	@for i in $(IMAGES); do docker build -t twin/$$i images/$$i || exit 1; done

deploy: build
	sudo -E containerlab deploy -t twin.clab.yml --reconfigure

destroy:
	sudo containerlab destroy -t twin.clab.yml --cleanup

redeploy: destroy deploy

test:
	./tests/connectivity.sh $(SCENARIO)

inspect:
	sudo containerlab inspect -t twin.clab.yml

graph:
	sudo containerlab graph -t twin.clab.yml

attack:
	@echo "Suite d'attaques : prevue en semaine 5"
