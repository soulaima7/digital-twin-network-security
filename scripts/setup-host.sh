#!/usr/bin/env bash
# Installation des outils sur Ubuntu 24.04 (a lancer une seule fois)
set -e
sudo apt-get update
sudo apt-get install -y git make curl ca-certificates
# Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"
# Containerlab
bash -c "$(curl -sL https://get.containerlab.dev)"
# Module noyau 802.1Q (VLANs) charge maintenant et a chaque demarrage
sudo modprobe 8021q
echo 8021q | sudo tee /etc/modules-load.d/8021q.conf >/dev/null
echo
echo "OK. Deconnectez-vous puis reconnectez-vous (ou redemarrez) pour utiliser docker sans sudo."
docker --version || true
containerlab version || true
