#!/usr/bin/env python3
"""
ai/autoban.py - Digital Twin for Network Security (semaine 3)

Surveille en continu le journal eve.json de Suricata (sur le noeud fw) et
bannit automatiquement, via nftables, toute source qui declenche 5 alertes
ou plus en moins de 60 secondes.

Regle (cahier des charges 4.4 + Annexe D) :
    5 alertes Suricata en 60 s depuis la meme IP
        -> nft add element inet filter banned { <ip> timeout 15m }
        -> une ligne "BAN" dans results/ban.log
        -> Prometheus (semaine 4) detecte la hausse du nombre d'IP bannies
        -> notification Telegram/e-mail aux administrateurs

Le client LAN (10.10.10.10) est en liste de confiance : il ne sera jamais
banni, meme s'il declenche des alertes (faux positifs du generateur de
trafic normal par exemple).

Ce script n'a de sens qu'en scenario DURCI : le set nftables "banned"
n'existe que dans configs/hardened/nftables.conf. Il est lance par
images/fw/start.sh uniquement quand SCENARIO=hardened.
"""
import json
import os
import subprocess
import sys
import time
from collections import defaultdict, deque

EVE_JSON = os.environ.get("EVE_JSON_PATH", "/var/log/suricata/eve.json")
BAN_LOG = os.environ.get("BAN_LOG_PATH", "/results/ban.log")

ALERT_THRESHOLD = 5          # nombre d'alertes ...
WINDOW_SECONDS = 60          # ... dans cette fenetre glissante ...
BAN_TIMEOUT_NFT = "15m"      # ... declenche un bannissement de 15 minutes
BAN_TIMEOUT_SECONDS = 15 * 60

NFT_TABLE = "inet filter"
NFT_SET = "banned"

# Adresses jamais bannies : le client LAN (liste de confiance, cahier des
# charges 4.4) et les passerelles du pare-feu lui-meme (securite supplementaire,
# un pare-feu qui se bannirait lui-meme n'aurait pas de sens).
TRUSTED_IPS = {
    "10.10.10.10",   # client LAN - liste de confiance explicite du cahier des charges
    "10.10.10.1", "10.10.20.1", "10.10.30.1",  # passerelles fw
}


def log(msg: str) -> None:
    print(f"[autoban] {msg}", flush=True)


def tail_f(path: str):
    """Genere les nouvelles lignes ajoutees a `path`, comme `tail -f`.

    Attend que le fichier existe, se place a la fin (on ne traite que les
    alertes generees APRES le demarrage de l'auto-ban), puis relit en boucle.
    Tolere la rotation/troncature du fichier (reouvre si la taille diminue).
    """
    while not os.path.exists(path):
        time.sleep(1)

    f = open(path, "r")
    f.seek(0, os.SEEK_END)
    inode_size = os.fstat(f.fileno()).st_size

    while True:
        line = f.readline()
        if line:
            yield line
            continue

        # Pas de nouvelle ligne : verifie une eventuelle rotation du fichier
        try:
            current_size = os.stat(path).st_size
        except FileNotFoundError:
            current_size = 0
        if current_size < inode_size:
            f.close()
            f = open(path, "r")
        inode_size = current_size
        time.sleep(0.5)


def nft_ban(ip: str) -> bool:
    """Ajoute `ip` au set nftables `banned` avec un timeout de 15 minutes."""
    cmd = ["nft", "add", "element", NFT_TABLE, NFT_SET,
           "{", ip, "timeout", BAN_TIMEOUT_NFT, "}"]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        return True
    except FileNotFoundError:
        log("ERREUR : commande 'nft' introuvable (image fw sans nftables ?)")
        return False
    except subprocess.CalledProcessError as exc:
        log(f"ERREUR nft (le set '{NFT_SET}' existe-t-il ? scenario durci ?) : "
            f"{exc.stderr.strip()}")
        return False


def write_ban_log(ip: str, alert_count: int) -> None:
    os.makedirs(os.path.dirname(BAN_LOG), exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    line = (f"{ts} BAN src={ip} alerts={alert_count}/{WINDOW_SECONDS}s "
            f"timeout={BAN_TIMEOUT_NFT}\n")
    with open(BAN_LOG, "a") as fh:
        fh.write(line)
    log(line.strip())


def main() -> None:
    log(f"demarrage - surveillance de {EVE_JSON}")
    log(f"regle : {ALERT_THRESHOLD} alertes / {WINDOW_SECONDS}s -> ban {BAN_TIMEOUT_NFT}"
        f" (sources de confiance : {sorted(TRUSTED_IPS)})")

    # src_ip -> deque des horodatages (epoch) des dernieres alertes
    alert_times: dict[str, deque] = defaultdict(deque)
    already_banned: dict[str, float] = {}  # src_ip -> epoch du bannissement

    for raw_line in tail_f(EVE_JSON):
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            event = json.loads(raw_line)
        except json.JSONDecodeError:
            continue  # ligne partielle (ecriture concurrente) : ignoree

        if event.get("event_type") != "alert":
            continue

        src_ip = event.get("src_ip")
        if not src_ip:
            continue

        now = time.time()

        # Un bannissement local expire : on repart sur une fenetre propre
        if src_ip in already_banned and now - already_banned[src_ip] > BAN_TIMEOUT_SECONDS:
            del already_banned[src_ip]
            alert_times[src_ip].clear()

        if src_ip in already_banned:
            continue  # deja banni : pas besoin de recompter

        dq = alert_times[src_ip]
        dq.append(now)
        while dq and now - dq[0] > WINDOW_SECONDS:
            dq.popleft()

        sig = event.get("alert", {}).get("signature", "?")
        log(f"alerte src={src_ip} sig=\"{sig}\" ({len(dq)}/{ALERT_THRESHOLD} "
            f"sur {WINDOW_SECONDS}s)")

        if len(dq) < ALERT_THRESHOLD:
            continue

        if src_ip in TRUSTED_IPS:
            log(f"source de confiance {src_ip} : seuil atteint mais JAMAIS bannie")
            dq.clear()
            continue

        if nft_ban(src_ip):
            already_banned[src_ip] = now
            write_ban_log(src_ip, len(dq))
            dq.clear()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
