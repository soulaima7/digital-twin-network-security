# Machine d'attaque (zone ATK, simule Internet)
# Outils du cahier des charges 4.6 : nmap (scan), hydra (brute force SSH),
# apache2-utils/ab (surcharge HTTP). La suite d'attaques /opt/attack.sh et
# sa wordlist sont integrees a l'image ; elles ne sont JAMAIS lancees au
# demarrage (CMD sleep infinity), uniquement a la demande via
# "make attack SCENARIO=..." (docker exec). L'attaquant vise toujours le
# seul service publie 10.10.20.10, jamais le reseau de gestion.
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute curl netcat-openbsd procps \
      nmap hydra apache2-utils \
    && rm -rf /var/lib/apt/lists/*
COPY attack.sh /opt/attack.sh
COPY wordlist.txt /opt/wordlist.txt
RUN chmod +x /opt/attack.sh
CMD ["sleep", "infinity"]
