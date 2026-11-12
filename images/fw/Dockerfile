# Pare-feu / routeur central : nftables + Suricata (IDS) + auto-ban
#
# Le jeu de regles ET Open est recupere ET integre au build (suricata-update),
# ce qui permet un fonctionnement totalement hors ligne une fois l'image
# construite (cahier des charges 4.4). Needs internet access at build time.
#
# configs/suricata/suricata.yaml et ai/autoban.py NE SONT PAS copies ici :
# comme nftables.conf, ils sont montes par Containerlab (twin.clab.yml), afin
# que l'image reste strictement identique entre les deux scenarios -- seul
# ce qui est lance au demarrage (voir start.sh) depend de SCENARIO.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute nftables tcpdump ethtool procps \
      prometheus-node-exporter \
      suricata python3 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && suricata-update enable-source et/open \
    && suricata-update

COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
