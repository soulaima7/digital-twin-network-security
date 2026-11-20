#!/usr/bin/env python3
"""Affiche l'etat des cibles Prometheus (make monitor-check)."""
import json
import sys
import urllib.request

try:
    data = json.load(urllib.request.urlopen("http://localhost:9090/api/v1/targets", timeout=3))
except OSError as exc:
    sys.exit(f"ECHEC : Prometheus injoignable sur :9090 ({exc})")
for t in data["data"]["activeTargets"]:
    name = t["labels"].get("node", t["labels"]["job"])
    print(f"{name:8} {t['health']:5} {t['scrapeUrl']}")
