#!/usr/bin/env python3
"""
analysis/attack_windows.py - Digital Twin for Network Security (semaine 6)

Construit results/attack_windows.json (intervalles d'attaque, en epoch) a
partir des horodatages ecrits par /opt/attack.sh :
    results/attack_start_<scenario>.txt   (ligne ISO + ligne epoch)
    results/attack_end_<scenario>.txt     (epoch)

Ce fichier sert a etiqueter les fenetres pour la matrice de confusion
(ai/anomaly.py evaluate). Par defaut on prend le scenario durci, le seul
ou Suricata (et donc eve.json) tourne.

Usage :
    python3 analysis/attack_windows.py [hardened|baseline ...]
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "results")


def epoch_from(path, last_line=False):
    try:
        with open(path) as fh:
            lines = [ln.strip() for ln in fh if ln.strip()]
    except OSError:
        return None
    for ln in (reversed(lines) if last_line else lines):
        if ln.isdigit():
            return float(ln)
    return None


def main():
    scenarios = sys.argv[1:] or ["hardened"]
    intervals = []
    for sc in scenarios:
        start = epoch_from(os.path.join(RESULTS, f"attack_start_{sc}.txt"), last_line=True)
        end = epoch_from(os.path.join(RESULTS, f"attack_end_{sc}.txt"))
        if start is None:
            print(f"[attack_windows] pas d'horodatage pour '{sc}' "
                  f"(lancer make attack SCENARIO={sc})")
            continue
        if end is None:
            end = start + 120   # repli : duree indicative
        intervals.append({"scenario": sc, "start": start, "end": end})

    out = os.path.join(RESULTS, "attack_windows.json")
    os.makedirs(RESULTS, exist_ok=True)
    with open(out, "w") as fh:
        json.dump(intervals, fh, indent=2)
    print(f"{len(intervals)} intervalle(s) -> {out}")


if __name__ == "__main__":
    main()
