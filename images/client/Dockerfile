# Poste utilisateur LAN : genere du trafic normal (traffic.sh) et sert aussi
# d'utilisateur "legitime" pour les tests SSH de durcissement (tests/connectivity.sh)
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute curl netcat-openbsd procps coreutils \
      openssh-client sshpass \
      prometheus-node-exporter \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p -m 700 /root/.ssh
COPY start.sh /start.sh
COPY traffic.sh /usr/local/bin/traffic.sh
RUN chmod +x /start.sh /usr/local/bin/traffic.sh
CMD ["/start.sh"]
