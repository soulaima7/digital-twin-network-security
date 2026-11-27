#!/usr/bin/env python3
"""
analysis/score.py - Digital Twin for Network Security (semaine 5)

Lit les sorties brutes d'une execution de /opt/attack.sh pour UN scenario
(baseline ou hardened) et calcule un score de securite sur 100
(cahier des charges 4.6).

Metriques extraites :
    Ports exposes        nombre de "open" dans la sortie nmap
    Succes brute force   presence d'une ligne "login:" dans la sortie hydra
    Temps de detection   premiere alerte Suricata (eve.json) - debut de l'attaque
    Temps de bannissement premiere ligne BAN (results/ban.log) - debut de l'attaque
    Disponibilite        % de requetes reussies dans la sortie ab

Bareme (on part de 100) :
    -30  si le brute force SSH reussit
    -20  si plus de 3 ports sont exposes
    -20  si aucune alerte Suricata dans les 30 premieres secondes
    -20  si l'attaquant n'est jamais banni
    -10  si la disponibilite passe sous 90 %

Les fichiers attendus (dans results/, ecrits par attack.sh et les phases
precedentes), suffixes par le scenario :
    results/attack_start_<scenario>.txt   ligne ISO + ligne epoch (debut)
    results/nmap_<scenario>.txt           sortie nmap
    results/hydra_<scenario>.txt          sortie hydra (-o, succes seulement)
    results/ab_<scenario>.txt             sortie ab
    logs/eve.json                         journal Suricata (hardened uniquement)
    results/ban.log                       journal des bannissements (hardened)

Sortie : un dictionnaire JSON dans results/score_<scenario>.json et un
resume lisible sur la sortie standard. compare.py agrege ensuite les deux
scenarios en un tableau et un graphique.

Usage :
    python3 analysis/score.py baseline
    python3 analysis/score.py hardened
"""
import json
import os
import re
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS = os.path.join(REPO, "results")
LOGS = os.path.join(REPO, "logs")

ATTACKER_IP = "10.10.30.10"
WEB_IP = "10.10.20.10"
DETECTION_WINDOW = 30          # s : alerte attendue dans ce delai
AVAILABILITY_FLOOR = 90.0      # % en-dessous duquel on retire 10 points


# --------------------------------------------------------------------- lecture
def read_text(path):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def attack_start_epoch(scenario):
    """Epoch (float) du debut de l'attaque, ecrit par attack.sh."""
    txt = read_text(os.path.join(RESULTS, f"attack_start_{scenario}.txt"))
    for line in txt.splitlines():
        line = line.strip()
        if line.isdigit():
            return float(line)
    return None


# --------------------------------------------------------------- metriques
def count_open_ports(scenario):
    """Nombre de lignes '<port>/tcp open' dans la sortie nmap."""
    txt = read_text(os.path.join(RESULTS, f"nmap_{scenario}.txt"))
    return len(re.findall(r"^\s*\d+/tcp\s+open\b", txt, re.MULTILINE))


def bruteforce_succeeded(scenario):
    """True si hydra a trouve un couple identifiant/mot de passe."""
    # hydra -o n'ecrit la ligne "[22][ssh] ... login: ... password: ..."
    # qu'en cas de succes.
    txt = read_text(os.path.join(RESULTS, f"hydra_{scenario}.txt"))
    if re.search(r"login:\s*\S+\s+password:\s*\S+", txt):
        return True
    # Repli : certains builds n'ecrivent le resultat que sur stdout.
    txt = read_text(os.path.join(RESULTS, f"hydra_stdout_{scenario}.txt"))
    return bool(re.search(r"\[22\]\[ssh\].*login:\s*\S+\s+password:\s*\S+", txt))


def availability_percent(scenario):
    """% de requetes HTTP reussies d'apres la sortie ab."""
    txt = read_text(os.path.join(RESULTS, f"ab_{scenario}.txt"))
    complete = re.search(r"Complete requests:\s*(\d+)", txt)
    failed = re.search(r"Failed requests:\s*(\d+)", txt)
    total = re.search(r"Total(?: of)?\s+(\d+)\s+requests", txt)  # tolerance
    n_complete = int(complete.group(1)) if complete else 0
    n_failed = int(failed.group(1)) if failed else 0
    # ab : "Complete requests" compte les reponses recues (echecs inclus) ;
    # on soustrait les "Failed requests" pour obtenir les reussites reelles.
    n_total = int(total.group(1)) if total else (n_complete if n_complete else 5000)
    if n_total <= 0:
        return 0.0
    success = max(0, n_complete - n_failed)
    return round(100.0 * success / n_total, 1)


def first_suricata_alert_epoch(since_epoch):
    """Epoch de la premiere alerte Suricata posterieure au debut de l'attaque.

    L'attaquant (10.10.30.10) est la seule source pertinente : on ignore les
    alertes eventuelles du trafic normal. En baseline, eve.json n'existe pas
    (Suricata n'est pas lance) -> None.
    """
    path = os.path.join(LOGS, "eve.json")
    best = None
    txt = read_text(path)
    for line in txt.splitlines():
        line = line.strip()
        if not line or '"event_type":"alert"' not in line.replace(" ", ""):
            if '"alert"' not in line:
                continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("event_type") != "alert":
            continue
        if ev.get("src_ip") != ATTACKER_IP:
            continue
        ts = parse_eve_timestamp(ev.get("timestamp", ""))
        if ts is None or (since_epoch is not None and ts < since_epoch - 2):
            continue
        if best is None or ts < best:
            best = ts
    return best


def parse_eve_timestamp(ts):
    """Convertit un timestamp Suricata ISO (avec fuseau) en epoch UTC (float).

    Format Suricata : 2026-11-20T03:08:12.123456+0100
    On lit la partie locale, on la traite comme UTC (calendar.timegm) puis on
    retire le decalage du fuseau pour obtenir un vrai epoch UTC.
    """
    if not ts:
        return None
    m = re.match(
        r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?([+-])(\d{2}):?(\d{2})?", ts
    )
    if not m:
        return None
    base, sign, tzh, tzm = m.group(1), m.group(2), m.group(3), m.group(4) or "00"
    local_epoch = _iso_to_utc_epoch(base)
    if local_epoch is None:
        return None
    offset = (int(tzh) * 3600 + int(tzm) * 60) * (1 if sign == "+" else -1)
    return local_epoch - offset


def _iso_to_utc_epoch(base):
    """Interprete 'YYYY-MM-DDTHH:MM:SS' comme une date UTC et renvoie l'epoch."""
    import calendar
    try:
        return calendar.timegm(time.strptime(base, "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, OverflowError):
        return None


def first_ban_epoch(scenario, since_epoch):
    """Epoch de la premiere ligne BAN de l'attaquant apres le debut de l'attaque."""
    path = os.path.join(RESULTS, "ban.log")
    best = None
    for line in read_text(path).splitlines():
        if " BAN " not in line or ATTACKER_IP not in line:
            continue
        m = re.match(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line.strip())
        if not m:
            continue
        ts = _iso_to_utc_epoch(m.group(1))   # ban.log est horodate en UTC (gmtime)
        if since_epoch is not None and ts < since_epoch - 2:
            continue
        if best is None or ts < best:
            best = ts
    return best


# --------------------------------------------------------------- scoring
def compute_score(m):
    """Applique le bareme du cahier des charges et renvoie (score, details)."""
    score = 100
    deductions = []

    if m["bruteforce_success"]:
        score -= 30
        deductions.append(("-30", "brute force SSH reussi"))
    if m["open_ports"] > 3:
        score -= 20
        deductions.append(("-20", f"{m['open_ports']} ports exposes (> 3)"))

    det = m["detection_seconds"]
    if det is None or det > DETECTION_WINDOW:
        score -= 20
        why = "aucune alerte Suricata" if det is None else f"detection en {det:.0f}s (> {DETECTION_WINDOW}s)"
        deductions.append(("-20", why))

    if m["ban_seconds"] is None:
        score -= 20
        deductions.append(("-20", "attaquant jamais banni"))

    if m["availability_percent"] < AVAILABILITY_FLOOR:
        score -= 10
        deductions.append(("-10", f"disponibilite {m['availability_percent']}% (< {AVAILABILITY_FLOOR}%)"))

    return max(0, score), deductions


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("baseline", "hardened"):
        print("Usage: python3 analysis/score.py baseline|hardened")
        sys.exit(2)
    scenario = sys.argv[1]

    start = attack_start_epoch(scenario)
    alert = first_suricata_alert_epoch(start)
    ban = first_ban_epoch(scenario, start)

    metrics = {
        "scenario": scenario,
        "attack_start_epoch": start,
        "open_ports": count_open_ports(scenario),
        "bruteforce_success": bruteforce_succeeded(scenario),
        "availability_percent": availability_percent(scenario),
        "detection_seconds": (round(alert - start, 1) if (alert and start) else None),
        "ban_seconds": (round(ban - start, 1) if (ban and start) else None),
    }
    score, deductions = compute_score(metrics)
    metrics["score"] = score
    metrics["deductions"] = deductions

    os.makedirs(RESULTS, exist_ok=True)
    out = os.path.join(RESULTS, f"score_{scenario}.json")
    with open(out, "w") as fh:
        json.dump(metrics, fh, indent=2)

    # ---- resume lisible ----
    print(f"=== Score de securite - scenario {scenario.upper()} ===")
    print(f"  Ports exposes (nmap)        : {metrics['open_ports']}")
    print(f"  Brute force SSH reussi       : {'OUI' if metrics['bruteforce_success'] else 'non'}")
    det = metrics["detection_seconds"]
    print(f"  Temps de detection Suricata  : {det if det is not None else 'jamais'}"
          f"{'s' if det is not None else ''}")
    bans = metrics["ban_seconds"]
    print(f"  Temps de bannissement        : {bans if bans is not None else 'jamais'}"
          f"{'s' if bans is not None else ''}")
    print(f"  Disponibilite (ab)           : {metrics['availability_percent']} %")
    print("  Deductions :")
    for pts, why in deductions:
        print(f"    {pts}  {why}")
    if not deductions:
        print("    (aucune - score maximal)")
    print(f"  --> SCORE : {score}/100")
    print(f"  (detail : {out})")


if __name__ == "__main__":
    main()
