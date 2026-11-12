# Serveur DMZ : nginx + SSH
# La difference baseline / durci vient uniquement des fichiers de
# configuration montes par Containerlab (configs/${SCENARIO}/...) et
# du certificat / de la cle SSH generes dans ./secrets -- l'image est
# strictement la meme pour les deux scenarios (Infrastructure as Code).
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      iproute2 iputils-ping traceroute nginx openssh-server openssl procps \
      prometheus-node-exporter \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /etc/ssh/authorized_keys /etc/nginx/ssl

# Compte de test, utilise :
#   - scenario baseline : connexion par mot de passe (testuser / password123)
#   - scenario durci     : connexion par cle uniquement (PasswordAuthentication no),
#                          le mot de passe ci-dessous devient alors sans effet.
RUN useradd -m -s /bin/bash testuser \
    && echo 'testuser:password123' | chpasswd \
    && chmod 700 /home/testuser \
    && mkdir -p /home/testuser/.ssh && chown testuser:testuser /home/testuser/.ssh

RUN echo '<h1>Digital Twin - serveur web DMZ (10.10.20.10)</h1>' > /var/www/html/index.html

COPY start.sh /start.sh
RUN chmod +x /start.sh
CMD ["/start.sh"]
