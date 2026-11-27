#!/usr/bin/env python3
"""
analysis/compare.py - Digital Twin for Network Security (semaine 5)

Agrege les resultats des deux scenarios (results/score_baseline.json et
results/score_hardened.json, produits par score.py) en :

  1. un tableau comparatif avant/apres (console + results/compare_table.md) ;
  2. un graphique en barres du score de securite (matplotlib) :
     results/compare_scores.png.

C'est le livrable central du projet (cahier des charges 4.6 / 6) : il montre
objectivement l'ecart entre le reseau baseline (faible) et le reseau durci.

Usage :
    python3 analysis/score.py baseline
    python3 analysis/score.py hardened
    python3 analysis/compare.py
"""
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "results")

import matplotlib
matplotlib.use("Agg")           # pas d'affichage : on ecrit un PNG
import matplotlib.pyplot as plt


def load(scenario):
    path = os.path.join(RESULTS, f"score_{scenario}.json")
    try:
        with open(path) as fh:
            return json.load(fh)
    except OSError:
        print(f"ERREUR : {path} introuvable. Lancer d'abord :")
        print(f"         make attack SCENARIO={scenario} && make score SCENARIO={scenario}")
        return None


def fmt_seconds(v):
    return "jamais" if v is None else f"{v:.0f}s"


def yesno(v):
    return "OUI" if v else "non"


ROWS = [
    ("Ports exposes (nmap)",        lambda d: str(d["open_ports"])),
    ("Brute force SSH reussi",      lambda d: yesno(d["bruteforce_success"])),
    ("Temps de detection Suricata", lambda d: fmt_seconds(d["detection_seconds"])),
    ("Temps de bannissement",       lambda d: fmt_seconds(d["ban_seconds"])),
    ("Disponibilite (ab)",          lambda d: f"{d['availability_percent']} %"),
    ("SCORE /100",                  lambda d: str(d["score"])),
]


def build_table(base, hard):
    lines = []
    lines.append(f"| {'Metrique':<30} | {'Baseline':>12} | {'Durci':>12} |")
    lines.append(f"|{'-'*32}|{'-'*14}|{'-'*14}|")
    for label, get in ROWS:
        lines.append(f"| {label:<30} | {get(base):>12} | {get(hard):>12} |")
    return "\n".join(lines)


def bar_chart(base, hard, out_png):
    scenarios = ["Baseline", "Durci"]
    scores = [base["score"], hard["score"]]
    colors = ["#d64545", "#2f9e44"]   # rouge faible / vert durci

    fig, ax = plt.subplots(figsize=(6, 4.5))
    bars = ax.bar(scenarios, scores, color=colors, width=0.55, edgecolor="black", linewidth=0.6)
    ax.set_ylim(0, 100)
    ax.set_ylabel("Score de securite / 100")
    ax.set_title("Score de securite du jumeau : baseline vs durci")
    ax.axhline(50, color="grey", linestyle=":", linewidth=0.8)
    for bar, s in zip(bars, scores):
        ax.text(bar.get_x() + bar.get_width() / 2, s + 2, str(s),
                ha="center", va="bottom", fontweight="bold")
    ax.grid(axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(out_png, dpi=130)
    plt.close(fig)


def main():
    base = load("baseline")
    hard = load("hardened")
    if not base or not hard:
        sys.exit(1)

    table = build_table(base, hard)
    print(table)
    print()

    delta = hard["score"] - base["score"]
    verdict = (f"Le durcissement fait passer le score de {base['score']} a "
               f"{hard['score']}/100 (+{delta} points).")
    print(verdict)

    os.makedirs(RESULTS, exist_ok=True)
    md = os.path.join(RESULTS, "compare_table.md")
    with open(md, "w") as fh:
        fh.write("# Comparaison baseline / durci (semaine 5)\n\n")
        fh.write(table + "\n\n" + verdict + "\n")

    png = os.path.join(RESULTS, "compare_scores.png")
    bar_chart(base, hard, png)
    print(f"\nTableau : {md}\nGraphique : {png}")


if __name__ == "__main__":
    main()
