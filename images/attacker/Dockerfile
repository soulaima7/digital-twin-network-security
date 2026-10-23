# Machine d'attaque (zone ATK, simule Internet)
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute curl netcat-openbsd procps \
      nmap hydra apache2-utils \
    && rm -rf /var/lib/apt/lists/*
CMD ["sleep", "infinity"]
