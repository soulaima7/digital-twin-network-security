# Pare-feu / routeur central (Suricata sera ajoute en semaine 3)
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute nftables tcpdump ethtool procps \
      prometheus-node-exporter \
    && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
