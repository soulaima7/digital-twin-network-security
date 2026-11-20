#!/usr/bin/env python3
"""
ai/exporter.py - Digital Twin for Network Security (semaine 4)

Exporter Prometheus du jumeau, lance sur l'HOTE (cahier des charges 4.5),
expose sur http://localhost:9200/metrics. Bibliotheque standard uniquement
(aucun pip install).

Metriques exposees :
  twin_suricata_alerts_total            alertes Suricata depuis le demarrage (counter)
  twin_suricata_alerts_by_src_total     idem, par IP source (counter, label src_ip)
  twin_suricata_alerts_per_minute       alertes des 60 dernieres secondes (gauge)
  twin_banned_ips                       IP actuellement dans le set nftables banned
  twin_bans_total                       lignes BAN dans results/ban.log (counter)
  twin_web_up                           1 si http://10.10.20.10 repond depuis le client
  twin_web_response_seconds             temps de reponse de cette requete
  twin_anomaly_score                    score d'anomalie IA (semaine 6, 0 en attendant)
  twin_anomaly_model_ready              1 quand results/anomaly_score existe
  twin_scenario_info{scenario=...}      scenario deploye (baseline / hardened)
  twin_eve_readable                     1 si logs/eve.json est lisible par l'exporter

Disponibilite du site : la requete part du CLIENT (docker exec clab-twin-client
curl http://10.10.20.10), donc par le plan de donnees et a travers le pare-feu,
comme un vrai utilisateur. Le reseau de gestion 172.20.20.x n'est pas utilise
pour cette mesure, car il contourne le pare-feu.
"""
import json
import os
import subprocess
import threading
import time
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVE_JSON = os.environ.get("EVE_JSON_PATH", os.path.join(REPO, "logs", "eve.json"))
BAN_LOG = os.environ.get("BAN_LOG_PATH", os.path.join(REPO, "results", "ban.log"))
ANOMALY_FILE = os.environ.get("ANOMALY_PATH", os.path.join(REPO, "results", "anomaly_score"))
PORT = int(os.environ.get("EXPORTER_PORT", "9200"))
PROBE_INTERVAL = 5           # secondes entre deux mesures web / nft
WEB_URL = "http://10.10.20.10/"
FW, CLIENT = "clab-twin-fw", "clab-twin-client"

lock = threading.Lock()
state = {
    "alerts_total": 0,
    "alerts_by_src": Counter(),
    "alert_times": deque(),
    "eve_readable": 0,
    "banned_ips": 0,
    "bans_total": 0,
    "web_up": 0,
    "web_seconds": 0.0,
    "anomaly_score": 0.0,
    "anomaly_ready": 0,
    "scenario": "none",
}


def log(msg: str) -> None:
    print(f"[exporter] {msg}", flush=True)


def run(cmd: list[str], timeout: float = 5) -> str | None:
    """Execute une commande, renvoie stdout ou None en cas d'echec."""
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout if res.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


# ---------------------------------------------------------------- eve.json
def follow_eve() -> None:
    """Suit eve.json comme tail -f ; tolere absence, troncature, droits."""
    f, pos, first_open = None, 0, True
    while True:
        if f is None:
            try:
                f = open(EVE_JSON, "rb")
                if first_open:              # demarrage : seules les nouvelles alertes
                    f.seek(0, os.SEEK_END)
                    first_open = False
                pos = f.tell()              # apres troncature : relu depuis le debut
                with lock:
                    state["eve_readable"] = 1
                log(f"lecture de {EVE_JSON}")
            except PermissionError:
                with lock:
                    state["eve_readable"] = 0
                log(f"ERREUR droits sur {EVE_JSON} (voir README : chmod / filemode)")
                time.sleep(10)
                continue
            except FileNotFoundError:
                with lock:
                    state["eve_readable"] = 0
                time.sleep(2)
                continue

        line = f.readline()
        if line:
            pos = f.tell()
            if not line.endswith(b"\n"):    # ligne en cours d'ecriture
                f.seek(pos - len(line))
                time.sleep(0.2)
                continue
            handle_event(line)
            continue

        try:
            st = os.stat(EVE_JSON)
            size, replaced = st.st_size, st.st_ino != os.fstat(f.fileno()).st_ino
        except FileNotFoundError:
            size, replaced = -1, True
        if size < pos or replaced:          # truncate -s 0 ou rotation
            f.close()
            f = None
            log("eve.json tronque ou remplace : reouverture")
            continue
        time.sleep(0.5)


def handle_event(line: bytes) -> None:
    try:
        ev = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return
    if ev.get("event_type") != "alert":
        return
    src = ev.get("src_ip", "unknown")
    now = time.time()
    with lock:
        state["alerts_total"] += 1
        state["alerts_by_src"][src] += 1
        state["alert_times"].append(now)


# ------------------------------------------------------------- probes
def probe_loop() -> None:
    while True:
        probe_once()
        time.sleep(PROBE_INTERVAL)


def probe_once() -> None:
    # 1. Site web vu depuis le client, a travers le pare-feu
    out = run(["docker", "exec", CLIENT, "curl", "-s", "-o", "/dev/null",
               "-m", "3", "-w", "%{http_code} %{time_total}", WEB_URL], timeout=6)
    web_up, web_s = 0, 0.0
    if out:
        try:
            code, secs = out.split()
            web_up = 1 if 200 <= int(code) < 400 else 0   # 301 vers HTTPS = OK
            web_s = float(secs)
        except ValueError:
            pass

    # 2. IP bannies : contenu reel du set nftables sur fw
    banned = 0
    out = run(["docker", "exec", FW, "nft", "-j", "list", "set", "inet", "filter", "banned"])
    if out:
        try:
            for item in json.loads(out).get("nftables", []):
                if "set" in item:
                    banned = len(item["set"].get("elem", []))
        except (json.JSONDecodeError, AttributeError):
            pass

    # 3. Scenario deploye
    out = run(["docker", "exec", FW, "printenv", "SCENARIO"])
    scenario = out.strip() if out else "none"

    # 4. Nombre total de bannissements (historique de ban.log)
    try:
        with open(BAN_LOG) as fh:
            bans = sum(1 for ln in fh if " BAN " in ln)
    except OSError:
        bans = 0

    # 5. Score d'anomalie (ecrit par l'IA en semaine 6)
    score, ready = 0.0, 0
    try:
        with open(ANOMALY_FILE) as fh:
            score, ready = float(fh.read().strip() or 0), 1
    except (OSError, ValueError):
        pass

    with lock:
        state.update(web_up=web_up, web_seconds=web_s, banned_ips=banned,
                     scenario=scenario, bans_total=bans,
                     anomaly_score=score, anomaly_ready=ready)


# -------------------------------------------------------------- /metrics
def esc(v: str) -> str:
    return v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render() -> str:
    now = time.time()
    with lock:
        dq = state["alert_times"]
        while dq and now - dq[0] > 60:
            dq.popleft()
        s = dict(state, per_minute=len(dq), by_src=dict(state["alerts_by_src"]))

    m = []

    def metric(name, mtype, help_, samples):
        m.append(f"# HELP {name} {help_}")
        m.append(f"# TYPE {name} {mtype}")
        for labels, value in samples:
            lab = "{" + ",".join(f'{k}="{esc(v)}"' for k, v in labels.items()) + "}" if labels else ""
            m.append(f"{name}{lab} {value}")

    metric("twin_suricata_alerts_total", "counter",
           "Alertes Suricata lues depuis le demarrage de l'exporter", [({}, s["alerts_total"])])
    metric("twin_suricata_alerts_by_src_total", "counter",
           "Alertes Suricata par IP source", [({"src_ip": k}, v) for k, v in sorted(s["by_src"].items())])
    metric("twin_suricata_alerts_per_minute", "gauge",
           "Alertes Suricata des 60 dernieres secondes", [({}, s["per_minute"])])
    metric("twin_banned_ips", "gauge",
           "IP actuellement dans le set nftables banned", [({}, s["banned_ips"])])
    metric("twin_bans_total", "counter",
           "Bannissements enregistres dans results/ban.log", [({}, s["bans_total"])])
    metric("twin_web_up", "gauge",
           "1 si le site web repond depuis le client (a travers fw)", [({}, s["web_up"])])
    metric("twin_web_response_seconds", "gauge",
           "Temps de reponse HTTP mesure depuis le client", [({}, s["web_seconds"])])
    metric("twin_anomaly_score", "gauge",
           "Score d'anomalie IA entre 0 et 1 (semaine 6)", [({}, s["anomaly_score"])])
    metric("twin_anomaly_model_ready", "gauge",
           "1 si le modele IA publie un score", [({}, s["anomaly_ready"])])
    metric("twin_scenario_info", "gauge",
           "Scenario deploye", [({"scenario": s["scenario"]}, 1)])
    metric("twin_eve_readable", "gauge",
           "1 si logs/eve.json est lisible", [({}, s["eve_readable"])])
    return "\n".join(m) + "\n"


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.split("?")[0] != "/metrics":
            self.send_response(404)
            self.end_headers()
            return
        body = render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main() -> None:
    log(f"demarrage sur :{PORT} - eve.json={EVE_JSON} ban.log={BAN_LOG}")
    threading.Thread(target=follow_eve, daemon=True).start()
    threading.Thread(target=probe_loop, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
