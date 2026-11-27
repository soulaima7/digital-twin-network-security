#!/usr/bin/env python3
"""
ai/explain.py - Digital Twin for Network Security (semaine 6, BONUS)

Explication des anomalies en langage clair via un LLM local (Ollama,
llama3.2:3b ~ 4 Go de RAM), cahier des charges 4.7 "Bonus".

Le script resume les fenetres anormales detectees par anomaly.py
(nombre d'alertes, ports, signatures, octets) et demande au modele local
une explication courte, lisible par un administrateur, de ce qui se passe
et de la pertinence des regles proposees par advisor.py.

Totalement optionnel et degradant proprement :
  - n'utilise que la bibliotheque standard (urllib) ;
  - si Ollama n'est pas lance (http://localhost:11434), affiche un resume
    factuel "hors ligne" a la place, sans erreur (le projet reste complet
    sans le bonus, cf. ordre d'abandon du cahier des charges : Ollama en
    premier).

Usage :
    ollama serve &                 # si pas deja lance
    ollama pull llama3.2:3b
    python3 ai/explain.py --eve logs/eve.json
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ai"))
import anomaly as A

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:3b")
TRUSTED_IPS = {"10.10.10.10", "10.10.10.1", "10.10.20.1", "10.10.30.1"}


def summarize(eve_path, threshold):
    """Construit un resume factuel des fenetres anormales (pour le prompt)."""
    bundle = A.load_model() if os.path.exists(A.MODEL_PATH) else None
    windows = A.windowize(eve_path)
    if not windows:
        return None, []
    if bundle:
        X = A.feature_matrix(windows)
        scores = A.anomaly_scores(bundle["model"], bundle["scaler"], bundle["calib"], X)
    else:
        scores = [1.0 if w["n_alerts"] else 0.0 for w in windows]

    anomalous = []
    for w, s in zip(windows, scores):
        if s > threshold:
            anomalous.append({
                "score": round(float(s), 3),
                "alerts": w["n_alerts"],
                "unique_dports": w["n_unique_dports"],
                "unique_sigs": w["n_unique_sigs"],
                "flows": w["n_flows"],
                "bytes": w["bytes"],
                "src_ips": [ip for ip in w["src_ips"] if ip not in TRUSTED_IPS],
            })
    return anomalous, scores


def build_prompt(anomalous):
    facts = json.dumps(anomalous, indent=2)
    return (
        "Tu es un analyste securite reseau. Voici des fenetres d'une minute "
        "jugees anormales par un modele Isolation Forest, dans un laboratoire "
        "(jumeau numerique). Chaque fenetre indique le nombre d'alertes Suricata, "
        "les ports de destination uniques, les signatures uniques, le nombre de "
        "flux, les octets et les IP sources.\n\n"
        f"Donnees :\n{facts}\n\n"
        "En 4 a 6 phrases simples, en francais : explique ce qui se passe "
        "probablement (type d'attaque), pourquoi ces fenetres sont anormales par "
        "rapport a un trafic web normal, et si bloquer l'IP source et fermer les "
        "ports sondes est une reaction adaptee. Reste factuel et concis."
    )


def ask_ollama(prompt):
    payload = json.dumps({
        "model": OLLAMA_MODEL, "prompt": prompt, "stream": False,
        "options": {"temperature": 0.2},
    }).encode()
    req = urllib.request.Request(OLLAMA_URL, data=payload,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data.get("response", "").strip()


def offline_summary(anomalous):
    """Explication de repli (sans LLM) : factuelle, lisible."""
    if not anomalous:
        return "Aucune fenetre anormale : trafic conforme au profil normal appris."
    worst = max(anomalous, key=lambda a: a["alerts"])
    srcs = sorted({ip for a in anomalous for ip in a["src_ips"]})
    lines = [
        f"{len(anomalous)} fenetre(s) anormale(s) detectee(s).",
        f"Source(s) en cause : {', '.join(srcs) or 'inconnue'}.",
        f"Fenetre la plus marquee : {worst['alerts']} alertes Suricata sur "
        f"{worst['unique_dports']} ports de destination differents "
        f"({worst['unique_sigs']} signatures), {worst['flows']} flux.",
        "Profil typique d'un balayage de ports (scan) : beaucoup de connexions "
        "vers de nombreux ports, peu d'octets par flux, contrairement a une "
        "navigation web normale (peu de ports, flux plus volumineux).",
        "Reaction adaptee : bloquer la source et fermer les ports sondes non "
        "publies (voir results/suggestions.nft), puis rejouer l'attaque pour "
        "verifier l'amelioration du score.",
    ]
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description="Explication des anomalies (LLM local, bonus)")
    p.add_argument("--eve", default=A.DEFAULT_EVE)
    p.add_argument("--threshold", type=float, default=0.7)
    args = p.parse_args()

    anomalous, _ = summarize(args.eve, args.threshold)
    if anomalous is None:
        print("eve.json vide : rien a expliquer.")
        return
    if not anomalous:
        print(offline_summary(anomalous))
        return

    prompt = build_prompt(anomalous)
    try:
        answer = ask_ollama(prompt)
        print("=== Explication (Ollama " + OLLAMA_MODEL + ") ===")
        print(answer or offline_summary(anomalous))
    except (urllib.error.URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"[explain] Ollama indisponible ({exc.__class__.__name__}) : "
              f"explication hors ligne a la place.")
        print("=== Explication (hors ligne) ===")
        print(offline_summary(anomalous))


if __name__ == "__main__":
    main()
