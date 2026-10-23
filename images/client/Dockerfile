# Poste utilisateur LAN (generateur de trafic en semaine 2)
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute curl netcat-openbsd procps \
      prometheus-node-exporter \
    && rm -rf /var/lib/apt/lists/*
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
