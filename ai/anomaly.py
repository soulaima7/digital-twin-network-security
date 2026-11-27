#!/usr/bin/env python3
"""
ai/anomaly.py - Digital Twin for Network Security (semaine 6)

Detection d'anomalies sur le trafic du jumeau par Isolation Forest
(cahier des charges 4.7).

Principe :
  * eve.json (Suricata) est decoupe en fenetres d'1 minute.
  * Chaque fenetre devient un vecteur de 5 caracteristiques :
        - nombre d'alertes
        - ports de destination uniques
        - signatures uniques
        - nombre de flux (event_type == flow)
        - octets echanges (bytes_toserver + bytes_toclient)
  * Un modele Isolation Forest (scikit-learn, contamination=0.05) est
    entraine sur 20 a 30 minutes de trafic NORMAL (client -> web, bruit
    de fond genere par traffic.sh, aucune attaque).
  * En exploitation, chaque nouvelle fenetre recoit un score d'anomalie
    entre 0 et 1 (1 = tres anormal). Le score de la derniere fenetre est
    ecrit dans results/anomaly_score, lu par ai/exporter.py puis publie
    dans Grafana (panneau + alerte "Score d'anomalie IA eleve" > 0.7,
    deja en place depuis la phase 3).

Sous-commandes :
    train     entraine le modele sur un eve.json de trafic normal
    score     calcule le score de la derniere fenetre et l'ecrit dans
              results/anomaly_score (one-shot, pour cron/Makefile)
    run       boucle : recalcule le score toutes les 60 s (demonstration live)
    evaluate  matrice de confusion a partir d'intervalles d'attaque connus

Modele standardise (StandardScaler) + IsolationForest, sauvegarde dans
ai/model/anomaly.joblib avec les parametres de calibration du score.

Exemples :
    python3 ai/anomaly.py train    --eve logs/eve_normal.json
    python3 ai/anomaly.py score    --eve logs/eve.json
    python3 ai/anomaly.py run      --eve logs/eve.json --interval 60
    python3 ai/anomaly.py evaluate --eve logs/eve.json --attacks results/attack_windows.json
"""
import argparse
import json
import math
import os
import time
from collections import defaultdict

import numpy as np

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_EVE = os.path.join(REPO, "logs", "eve.json")
MODEL_DIR = os.path.join(REPO, "ai", "model")
MODEL_PATH = os.path.join(MODEL_DIR, "anomaly.joblib")
SCORE_FILE = os.path.join(REPO, "results", "anomaly_score")

WINDOW_SECONDS = 60
CONTAMINATION = 0.02
FEATURES = ["n_alerts", "n_unique_dports", "n_unique_sigs", "n_flows", "bytes"]

# L'attaquant et les passerelles ne font pas partie du "trafic normal" : la
# detection d'anomalies raisonne au niveau de la fenetre temporelle, pas de
# l'IP, mais on documente ici l'IP attaquant pour l'etiquetage (evaluate).
ATTACKER_IP = "10.10.30.10"


# --------------------------------------------------------------- parsing eve
def parse_timestamp(ts):
    """Timestamp Suricata ISO (avec fuseau) -> epoch UTC (float)."""
    import calendar
    import re
    m = re.match(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-])(\d{2}):?(\d{2})?", ts or ""
    )
    if not m:
        return None
    base, sign, tzh, tzm = m.group(1), m.group(2), m.group(3), m.group(4) or "00"
    try:
        local = calendar.timegm(time.strptime(base, "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return None
    offset = (int(tzh) * 3600 + int(tzm) * 60) * (1 if sign == "+" else -1)
    return local - offset


def iter_events(eve_path):
    """Genere (epoch, event_dict) pour chaque ligne JSON valide de eve.json."""
    try:
        fh = open(eve_path, "r", errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_timestamp(ev.get("timestamp", ""))
            if ts is None:
                continue
            yield ts, ev


def windowize(eve_path):
    """Regroupe les evenements par fenetre d'1 minute.

    Renvoie une liste de dicts ordonnee par temps :
        {window_start, n_alerts, n_unique_dports, n_unique_sigs, n_flows,
         bytes, src_ips}
    """
    buckets = defaultdict(lambda: {
        "alerts": 0, "dports": set(), "sigs": set(),
        "flows": 0, "bytes": 0, "src_ips": set(),
    })
    for ts, ev in iter_events(eve_path):
        w = int(ts // WINDOW_SECONDS) * WINDOW_SECONDS
        b = buckets[w]
        et = ev.get("event_type")
        if et == "alert":
            b["alerts"] += 1
            if ev.get("dest_port") is not None:
                b["dports"].add(ev.get("dest_port"))
            sid = ev.get("alert", {}).get("signature_id")
            if sid is not None:
                b["sigs"].add(sid)
            if ev.get("src_ip"):
                b["src_ips"].add(ev["src_ip"])
        elif et == "flow":
            b["flows"] += 1
            flow = ev.get("flow", {})
            b["bytes"] += int(flow.get("bytes_toserver", 0) or 0)
            b["bytes"] += int(flow.get("bytes_toclient", 0) or 0)
            if ev.get("src_ip"):
                b["src_ips"].add(ev["src_ip"])

    windows = []
    for w in sorted(buckets):
        b = buckets[w]
        windows.append({
            "window_start": w,
            "n_alerts": b["alerts"],
            "n_unique_dports": len(b["dports"]),
            "n_unique_sigs": len(b["sigs"]),
            "n_flows": b["flows"],
            "bytes": b["bytes"],
            "src_ips": sorted(b["src_ips"]),
        })
    return windows


def feature_matrix(windows):
    return np.array([[w[f] for f in FEATURES] for w in windows], dtype=float)


# --------------------------------------------------------------- calibration
def anomaly_scores(model, scaler, calib, X):
    """Convertit decision_function -> score d'anomalie dans [0, 1].

    decision_function > 0 : normal ; < 0 : anormal (seuil appris via
    contamination). On passe par une sigmoide centree sur 0 et mise a
    l'echelle par l'ecart-type des scores d'entrainement, de sorte qu'une
    fenetre nettement anormale depasse 0.7 (seuil de l'alerte Grafana).
    """
    if len(X) == 0:
        return np.array([])
    d = model.decision_function(scaler.transform(X))
    k = calib["k"]
    # score = sigmoid(-k * d) : d=0 -> 0.5 ; d<0 -> >0.5 ; d>0 -> <0.5
    return 1.0 / (1.0 + np.exp(np.clip(k * d, -30, 30)))


# --------------------------------------------------------------- train
def cmd_train(args):
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib

    windows = windowize(args.eve)
    if len(windows) < 5:
        print(f"ERREUR : seulement {len(windows)} fenetres dans {args.eve}. "
              f"Il faut 20 a 30 minutes de trafic normal (cahier des charges 4.7).")
        return 1
    X = feature_matrix(windows)

    scaler = StandardScaler().fit(X)
    model = IsolationForest(
        n_estimators=200, contamination=CONTAMINATION,
        random_state=42, n_jobs=-1,
    ).fit(scaler.transform(X))

    # Calibration k : on vise que l'ecart-type de decision_function sur le
    # trafic normal corresponde a un ecart de score raisonnable. k choisi pour
    # qu'une fenetre a ~2 ecarts-types sous 0 atteigne ~0.9.
    d = model.decision_function(scaler.transform(X))
    std = float(np.std(d)) or 0.05
    k = 2.0 / std
    calib = {"k": k, "train_windows": len(windows), "train_std": std}

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump({"model": model, "scaler": scaler, "calib": calib,
                 "features": FEATURES}, MODEL_PATH)

    train_scores = anomaly_scores(model, scaler, calib, X)
    print(f"Modele entraine sur {len(windows)} fenetres de 1 min "
          f"({len(windows)} min de trafic normal).")
    print(f"  Caracteristiques : {FEATURES}")
    print(f"  contamination={CONTAMINATION}, k={k:.1f}")
    print(f"  Score d'anomalie sur le trafic normal : "
          f"moyenne={train_scores.mean():.3f}, max={train_scores.max():.3f}")
    print(f"  Modele : {MODEL_PATH}")
    return 0


# --------------------------------------------------------------- load
def load_model():
    import joblib
    if not os.path.exists(MODEL_PATH):
        print(f"ERREUR : modele absent ({MODEL_PATH}). Lancer d'abord : "
              f"python3 ai/anomaly.py train --eve <trafic_normal>")
        return None
    return joblib.load(MODEL_PATH)


def write_score(score):
    os.makedirs(os.path.dirname(SCORE_FILE), exist_ok=True)
    with open(SCORE_FILE, "w") as fh:
        fh.write(f"{score:.4f}\n")


# --------------------------------------------------------------- score (1-shot)
def cmd_score(args):
    bundle = load_model()
    if not bundle:
        return 1
    windows = windowize(args.eve)
    if not windows:
        print("Aucune fenetre a scorer (eve.json vide ?). Score ecrit : 0.0")
        write_score(0.0)
        return 0
    X = feature_matrix(windows)
    scores = anomaly_scores(bundle["model"], bundle["scaler"], bundle["calib"], X)
    last = windows[-1]
    last_score = float(scores[-1])
    write_score(last_score)
    print(f"Derniere fenetre ({time.strftime('%H:%M', time.gmtime(last['window_start']))} UTC) : "
          f"score d'anomalie = {last_score:.3f}")
    print(f"  {dict((f, last[f]) for f in FEATURES)}")
    print(f"  -> {SCORE_FILE} (lu par ai/exporter.py, publie dans Grafana)")
    if last_score > 0.7:
        print("  ALERTE : score > 0.7 (seuil Grafana). Lancer le conseiller : "
              "python3 ai/advisor.py")
    return 0


# --------------------------------------------------------------- run (loop)
def cmd_run(args):
    bundle = load_model()
    if not bundle:
        return 1
    print(f"Boucle de scoring toutes les {args.interval}s (Ctrl-C pour arreter).")
    try:
        while True:
            windows = windowize(args.eve)
            if windows:
                X = feature_matrix(windows)
                scores = anomaly_scores(bundle["model"], bundle["scaler"],
                                        bundle["calib"], X)
                s = float(scores[-1])
            else:
                s = 0.0
            write_score(s)
            print(f"{time.strftime('%H:%M:%S')} score={s:.3f}", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        return 0


# --------------------------------------------------------------- evaluate
def load_attack_windows(path):
    """Intervalles d'attaque connus : liste de [start_epoch, end_epoch]."""
    try:
        with open(path) as fh:
            data = json.load(fh)
    except OSError:
        return []
    out = []
    for item in data if isinstance(data, list) else data.get("attacks", []):
        if isinstance(item, dict):
            out.append((float(item["start"]), float(item["end"])))
        else:
            out.append((float(item[0]), float(item[1])))
    return out


def is_attack_window(window_start, intervals):
    """Une fenetre est 'attaque' si elle recouvre un intervalle d'attaque."""
    w0, w1 = window_start, window_start + WINDOW_SECONDS
    return any(a0 < w1 and a1 > w0 for a0, a1 in intervals)


def cmd_evaluate(args):
    bundle = load_model()
    if not bundle:
        return 1
    intervals = load_attack_windows(args.attacks)
    if not intervals:
        print(f"ERREUR : aucun intervalle d'attaque dans {args.attacks}.")
        print('  Format attendu : [{"start": <epoch>, "end": <epoch>}, ...]')
        return 1

    windows = windowize(args.eve)
    if not windows:
        print("Aucune fenetre dans eve.json.")
        return 1
    X = feature_matrix(windows)
    scores = anomaly_scores(bundle["model"], bundle["scaler"], bundle["calib"], X)

    thr = args.threshold
    tp = fp = tn = fn = 0
    for w, s in zip(windows, scores):
        truth = is_attack_window(w["window_start"], intervals)
        pred = s > thr
        if truth and pred:
            tp += 1
        elif truth and not pred:
            fn += 1
        elif not truth and pred:
            fp += 1
        else:
            tn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    print(f"=== Matrice de confusion (seuil score > {thr}) ===")
    print(f"  Fenetres totales : {total}  (attaque : {tp+fn}, normal : {tn+fp})")
    print()
    print("                 | predit ATTAQUE | predit NORMAL |")
    print(f"  reel ATTAQUE   | {tp:>14} | {fn:>13} |   (detectees / manquees)")
    print(f"  reel NORMAL    | {fp:>14} | {tn:>13} |   (fausses alertes / ok)")
    print()
    print(f"  Precision : {precision:.2f}   Rappel : {recall:.2f}   F1 : {f1:.2f}")

    report = {
        "threshold": thr, "total_windows": total,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(precision, 3), "recall": round(recall, 3),
        "f1": round(f1, 3),
    }
    os.makedirs(os.path.join(REPO, "results"), exist_ok=True)
    out = os.path.join(REPO, "results", "confusion_matrix.json")
    with open(out, "w") as fh:
        json.dump(report, fh, indent=2)
    print(f"  -> {out}")

    if args.plot:
        plot_confusion(tp, fp, tn, fn, os.path.join(REPO, "results", "confusion_matrix.png"))
        print(f"  -> {os.path.join(REPO, 'results', 'confusion_matrix.png')}")
    return 0


def plot_confusion(tp, fp, tn, fn, out_png):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    mat = np.array([[tp, fn], [fp, tn]])
    fig, ax = plt.subplots(figsize=(5, 4.5))
    im = ax.imshow(mat, cmap="Blues")
    ax.set_xticks([0, 1], ["predit\nATTAQUE", "predit\nNORMAL"])
    ax.set_yticks([0, 1], ["reel\nATTAQUE", "reel\nNORMAL"])
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(mat[i, j]), ha="center", va="center",
                    color="black", fontsize=16, fontweight="bold")
    ax.set_title("Matrice de confusion - detection d'anomalies")
    fig.colorbar(im, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(out_png, dpi=130)
    plt.close(fig)


# --------------------------------------------------------------- main
def main():
    p = argparse.ArgumentParser(description="Detection d'anomalies (Isolation Forest)")
    sub = p.add_subparsers(dest="cmd", required=True)

    pt = sub.add_parser("train", help="entraine sur un eve.json de trafic normal")
    pt.add_argument("--eve", default=os.path.join(REPO, "logs", "eve_normal.json"))
    pt.set_defaults(func=cmd_train)

    ps = sub.add_parser("score", help="score de la derniere fenetre -> results/anomaly_score")
    ps.add_argument("--eve", default=DEFAULT_EVE)
    ps.set_defaults(func=cmd_score)

    pr = sub.add_parser("run", help="boucle de scoring (demonstration live)")
    pr.add_argument("--eve", default=DEFAULT_EVE)
    pr.add_argument("--interval", type=int, default=60)
    pr.set_defaults(func=cmd_run)

    pe = sub.add_parser("evaluate", help="matrice de confusion (attaques connues)")
    pe.add_argument("--eve", default=DEFAULT_EVE)
    pe.add_argument("--attacks", default=os.path.join(REPO, "results", "attack_windows.json"))
    pe.add_argument("--threshold", type=float, default=0.7)
    pe.add_argument("--plot", action="store_true")
    pe.set_defaults(func=cmd_evaluate)

    args = p.parse_args()
    raise SystemExit(args.func(args))


if __name__ == "__main__":
    main()
