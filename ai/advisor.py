#!/usr/bin/env python3
"""
ai/advisor.py - Digital Twin for Network Security (semaine 6)

Conseiller de regles firewall (cahier des charges 4.7).

Boucle "l'IA propose, le jumeau valide" :
    1. anomaly.py marque certaines fenetres d'1 min comme anormales.
    2. advisor.py regroupe les alertes de ces fenetres par IP source et par
       port de destination, puis genere des regles nftables dans
       results/suggestions.nft.
    3. Un humain LIT ces regles (rien n'est applique automatiquement),
       les applique dans le jumeau durci, rejoue l'attaque (make attack)
       et compare le score (make score / make compare) : si le score
       s'ameliore, la regle est conservee.

Difference avec l'auto-ban (phase 2) : l'auto-ban reagit en temps reel et
bannit une IP pour 15 min (mesure volatile). Le conseiller propose des
regles PERSISTANTES et ciblees (blocage durable d'une source, fermeture de
ports precis reellement attaques), issues de l'analyse a posteriori des
fenetres anormales. Les deux sont complementaires.

Les regles generees ne touchent JAMAIS les adresses de confiance (client
LAN et passerelles du pare-feu).

Usage :
    python3 ai/advisor.py                      # utilise le modele + logs/eve.json
    python3 ai/advisor.py --eve logs/eve.json --threshold 0.7
    python3 ai/advisor.py --all                # toutes les alertes (sans modele)
"""
import argparse
import os
import sys
import time
from collections import defaultdict

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "ai"))
import anomaly as A          # reutilise windowize / feature_matrix / calibration

SUGGESTIONS = os.path.join(REPO, "results", "suggestions.nft")
WEB_IP = "10.10.20.10"

# Jamais proposer de bloquer ces adresses (coherent avec autoban.py).
TRUSTED_IPS = {"10.10.10.10", "10.10.10.1", "10.10.20.1", "10.10.30.1"}

# Ports legitimement publies vers la DMZ (cahier des charges / nftables durci).
PUBLISHED_PORTS = {22, 80, 443}


def anomalous_window_starts(eve_path, threshold):
    """Renvoie l'ensemble des debuts de fenetres jugees anormales par le modele.

    Si le modele n'existe pas, renvoie None (le mode --all prendra le relais).
    """
    bundle = A.load_model() if os.path.exists(A.MODEL_PATH) else None
    if not bundle:
        return None
    windows = A.windowize(eve_path)
    if not windows:
        return set()
    X = A.feature_matrix(windows)
    scores = A.anomaly_scores(bundle["model"], bundle["scaler"], bundle["calib"], X)
    return {w["window_start"] for w, s in zip(windows, scores) if s > threshold}


def collect_alerts(eve_path, window_starts):
    """Regroupe les alertes par (src_ip, dest_port).

    Si window_starts est None -> toutes les alertes (mode --all).
    Sinon -> seulement les alertes des fenetres anormales.
    Renvoie :
        per_src   : src_ip -> {"ports": {dport: count}, "sigs": set, "total": n}
    """
    per_src = defaultdict(lambda: {"ports": defaultdict(int), "sigs": set(), "total": 0})
    for ts, ev in A.iter_events(eve_path):
        if ev.get("event_type") != "alert":
            continue
        if window_starts is not None:
            w = int(ts // A.WINDOW_SECONDS) * A.WINDOW_SECONDS
            if w not in window_starts:
                continue
        src = ev.get("src_ip")
        if not src or src in TRUSTED_IPS:
            continue
        dport = ev.get("dest_port")
        rec = per_src[src]
        rec["total"] += 1
        if dport is not None:
            rec["ports"][dport] += 1
        sid = ev.get("alert", {}).get("signature_id")
        if sid is not None:
            rec["sigs"].add(sid)
    return per_src


def build_rules(per_src):
    """Genere le texte de suggestions.nft a partir des sources regroupees."""
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    header = [
        "#!/usr/sbin/nft -f",
        "# =====================================================================",
        "#  suggestions.nft - regles proposees par l'IA (ai/advisor.py)",
        f"#  Genere le {ts}",
        "#",
        "#  NE PAS appliquer automatiquement. A LIRE, puis, apres validation :",
        "#    docker cp results/suggestions.nft clab-twin-fw:/tmp/suggestions.nft",
        "#    docker exec clab-twin-fw nft -f /tmp/suggestions.nft",
        "#  Puis rejouer l'attaque et comparer le score :",
        "#    make attack SCENARIO=hardened && make score SCENARIO=hardened && make compare",
        "#",
        "#  Les adresses de confiance (client LAN, passerelles) sont exclues.",
        "# =====================================================================",
        "",
    ]
    if not per_src:
        header.append("# Aucune source anormale detectee : rien a proposer.")
        return "\n".join(header) + "\n", []

    body = ["table inet filter {", "    chain forward {"]
    summary = []
    # Tri par volume d'alertes decroissant (source la plus active d'abord).
    for src, rec in sorted(per_src.items(), key=lambda kv: -kv[1]["total"]):
        ports = sorted(rec["ports"])
        attacked = [p for p in ports if p not in PUBLISHED_PORTS]
        n_ports = len(ports)
        body.append(f"        # {src} : {rec['total']} alertes, "
                    f"{n_ports} ports de destination, {len(rec['sigs'])} signatures")
        # 1. Blocage persistant de la source (sans timeout, contrairement a l'auto-ban)
        body.append(f"        ip saddr {src} drop")
        # 2. Fermeture ciblee des ports reellement sondes qui ne sont PAS publies
        if attacked:
            plist = ", ".join(str(p) for p in attacked[:20])
            more = "" if len(attacked) <= 20 else f"  # (+{len(attacked)-20} autres)"
            body.append(f"        # ports sondes non publies : fermeture explicite")
            body.append(f"        ip daddr {WEB_IP} tcp dport {{ {plist} }} drop{more}")
        body.append("")
        summary.append((src, rec["total"], n_ports, len(rec["sigs"])))
    body.append("    }")
    body.append("}")
    return "\n".join(header + body) + "\n", summary


def main():
    p = argparse.ArgumentParser(description="Conseiller de regles firewall (IA)")
    p.add_argument("--eve", default=A.DEFAULT_EVE)
    p.add_argument("--threshold", type=float, default=0.7,
                   help="seuil de score d'anomalie pour retenir une fenetre")
    p.add_argument("--all", action="store_true",
                   help="ignorer le modele et analyser toutes les alertes")
    args = p.parse_args()

    if args.all:
        window_starts = None
        mode = "toutes les alertes (mode --all)"
    else:
        window_starts = anomalous_window_starts(args.eve, args.threshold)
        if window_starts is None:
            window_starts = None
            mode = "toutes les alertes (modele absent : repli sur --all)"
        else:
            mode = f"{len(window_starts)} fenetre(s) anormale(s) (score > {args.threshold})"

    per_src = collect_alerts(args.eve, window_starts)
    text, summary = build_rules(per_src)

    os.makedirs(os.path.dirname(SUGGESTIONS), exist_ok=True)
    with open(SUGGESTIONS, "w") as fh:
        fh.write(text)

    print(f"Conseiller de regles - source d'analyse : {mode}")
    if not summary:
        print("  Aucune source anormale a bloquer.")
    else:
        print(f"  {len(summary)} source(s) anormale(s) -> regles proposees :")
        for src, total, nports, nsigs in summary:
            print(f"    {src:<15} {total:>4} alertes  {nports:>3} ports  {nsigs:>3} signatures")
    print(f"  -> {SUGGESTIONS}")
    print("  Etape suivante (validation humaine) :")
    print("    docker cp results/suggestions.nft clab-twin-fw:/tmp/suggestions.nft")
    print("    docker exec clab-twin-fw nft -f /tmp/suggestions.nft")
    print("    make attack SCENARIO=hardened && make score SCENARIO=hardened && make compare")


if __name__ == "__main__":
    main()
