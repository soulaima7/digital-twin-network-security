#!/usr/bin/env bash
# =====================================================================
#  Genere (si absents) les secrets du scenario durci :
#    - une paire de cles SSH pour l'administrateur (testuser)
#    - un certificat TLS auto-signe pour nginx
#  Idempotent : ne regenere rien si les fichiers existent deja, afin que
#  "make destroy / make deploy" ne change pas la cle a chaque cycle.
#  Appele automatiquement par "make prepare" (dependance de "make deploy").
# =====================================================================
set -e
cd "$(dirname "$0")/.."

mkdir -p secrets/ssh secrets/tls

# ---- Cle SSH de l'administrateur (scenario durci) ----
if [ ! -f secrets/ssh/web_admin ]; then
  ssh-keygen -t ed25519 -N "" -C "digital-twin-admin" -f secrets/ssh/web_admin -q
  echo "[gen-secrets] Nouvelle cle SSH : secrets/ssh/web_admin (privee) / web_admin.pub (publique)"
else
  echo "[gen-secrets] Cle SSH deja presente : secrets/ssh/web_admin"
fi

# ---- Certificat TLS auto-signe de nginx (scenario durci) ----
if [ ! -f secrets/tls/web.key ] || [ ! -f secrets/tls/web.crt ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days 825 -nodes \
    -keyout secrets/tls/web.key -out secrets/tls/web.crt \
    -subj "/C=TN/O=Digital Twin Lab/CN=web.twin.local" \
    -addext "subjectAltName=DNS:web.twin.local,IP:10.10.20.10" \
    2>/dev/null
  chmod 600 secrets/tls/web.key
  echo "[gen-secrets] Nouveau certificat TLS auto-signe : secrets/tls/web.crt / web.key"
else
  echo "[gen-secrets] Certificat TLS deja present : secrets/tls/web.crt"
fi

chmod 600 secrets/ssh/web_admin
chmod 644 secrets/ssh/web_admin.pub secrets/tls/web.crt
echo "[gen-secrets] OK - secrets prets dans ./secrets/"
