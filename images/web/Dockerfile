# Serveur DMZ : nginx + SSH (durcissement en semaine 2)
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute nginx openssh-server procps \
      prometheus-node-exporter \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd
RUN echo '<h1>Digital Twin - serveur web DMZ (10.10.20.10)</h1>' > /var/www/html/index.html
COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
