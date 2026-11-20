#!/usr/bin/env python3
"""Genere contactpoints.yml a partir du modele et des variables de monitoring/.env."""
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()
for key in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
    value = os.environ.get(key, "")
    if not value or value.startswith("123456789"):
        sys.exit(f"ERREUR : {key} manquant ou laisse a la valeur d'exemple dans monitoring/.env")
    text = text.replace("${" + key + "}", value)
open(dst, "w").write(text)
print(f"[alerting] {dst} genere")
