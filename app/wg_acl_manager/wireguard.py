"""Alles rund ums Lesen des WireGuard-Zustands auf dem Ziel: Ausfuehren von
Befehlen dort (SSH oder lokal), Peers/Namen/IPs aus der Config, Live-Status
per "wg show".
"""

import ipaddress
import re
import subprocess

from . import config

PEER_IP_COMMENT_RE = re.compile(r"^ip\s*:\s*(\S+)$", re.IGNORECASE)


def run_on_target(script: str, timeout: int = 15):
    """Fuehrt ein Bash-Script auf dem Ziel-WG-Server aus.

    EXEC_MODE=ssh (Standard): per SSH ueber einen eigenen, vom Container
    aufgebauten WireGuard-Tunnel auf einem separaten Rechner - das
    urspruengliche Least-Privilege-Design (Container sieht nur die
    Tunnel-IP des Ziels, nicht das ganze Mesh).

    EXEC_MODE=local: das Script laeuft direkt in diesem Container, ohne
    SSH und ohne eigenen Tunnel - fuer den Fall, dass wg-acl-manager auf
    dem WireGuard-Server selbst laeuft. Setzt voraus, dass der Container
    mit network_mode: host und cap_add: NET_ADMIN gestartet wird (siehe
    docker-compose.local.yml), damit "iptables"/"wg" hier dieselben
    Netzwerk-Namespaces wie der Host sehen.
    """
    if config.EXEC_MODE == "local":
        try:
            result = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                timeout=timeout,
            )
            ok = result.returncode == 0
            output = (result.stdout + result.stderr).decode(errors="replace")
            return ok, output
        except subprocess.TimeoutExpired:
            return False, "Timeout beim lokalen Ausfuehren des Scripts."
        except Exception as e:
            return False, f"Fehler bei lokaler Ausfuehrung: {e}"

    try:
        result = subprocess.run(
            [
                "ssh",
                "-i", config.SSH_KEY,
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=8",
                # Verbindung zwischen mehreren run_on_target()-Aufrufen (z.B.
                # bei "Alle anwenden" fuer viele Clients) wiederverwenden
                # statt jedes Mal neu aufzubauen.
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={config.SSH_CONTROL_DIR}/cm-%r@%h:%p",
                "-o", "ControlPersist=60s",
                f"{config.WG_SERVER_SSH_USER}@{config.WG_SERVER_TUNNEL_IP}",
                "bash", "-s",
            ],
            input=script.encode(),
            capture_output=True,
            timeout=timeout,
        )
        ok = result.returncode == 0
        output = (result.stdout + result.stderr).decode(errors="replace")
        return ok, output
    except subprocess.TimeoutExpired:
        return False, "Timeout - keine Antwort vom Zielserver innerhalb der Zeitgrenze."
    except Exception as e:
        return False, f"Fehler beim SSH-Aufruf: {e}"


def fetch_wg_status():
    ok, out = run_on_target(f"wg show {config.TARGET_WG_INTERFACE} dump")
    if not ok:
        return None, out
    peers = []
    for i, line in enumerate(out.strip().splitlines()):
        if i == 0:
            continue  # erste Zeile ist das Interface selbst
        parts = line.split("\t")
        if len(parts) < 7:
            continue  # unerwartetes Format - Zeile ueberspringen statt abzustuerzen
        pubkey, _, endpoint, allowed_ips, latest_hs, rx, tx = parts[:7]
        peers.append({
            "pubkey": pubkey,
            "endpoint": endpoint,
            "allowed_ips": allowed_ips,
            "latest_handshake": latest_hs,
            "rx": rx,
            "tx": tx,
        })
    return peers, None


def fetch_wg_peers_from_config():
    """Liest die WireGuard-Config auf dem Ziel und extrahiert je Peer Name,
    PublicKey, AllowedIPs und ggf. eine explizite eigene IP.

    Namenskonvention: die erste Zeile direkt unter [Peer] ist ein Kommentar
    mit dem Anzeigenamen der Verbindung, z.B.:

        [Peer]
        #Buero-Router
        PublicKey = ...
        AllowedIPs = 10.250.0.5/32

    Bei Peers mit weiterreichendem Routing-Zugriff deckt AllowedIPs kein
    einzelnes /32 mehr ab, sondern z.B. ein ganzes Subnetz (typisch fuer
    einen Admin-Rechner, der auf alle anderen Peers zugreifen darf) - dann
    laesst sich die eigene Tunnel-IP nicht mehr aus AllowedIPs ableiten.
    Fuer diesen Fall kann eine weitere Kommentarzeile im [Peer]-Block die
    tatsaechliche eigene IP angeben:

        [Peer]
        #PC-Admin
        #IP: 10.250.0.201
        PublicKey = ...
        AllowedIPs = 10.250.0.0/24

    Gibt eine Liste von dicts {"name", "pubkey", "allowed_ips", "actual_ip"}
    zurueck (leere Liste, falls die Config nicht lesbar ist). Zur
    IP-Ermittlung siehe peer_own_ip().
    """
    ok, out = run_on_target(f"cat /etc/wireguard/{config.TARGET_WG_INTERFACE}.conf 2>/dev/null")
    if not ok or not out.strip():
        return []

    peers = []
    current = None
    first_line_of_block = False
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("["):
            if current is not None:
                peers.append(current)
            if line.lower() == "[peer]":
                current = {"name": None, "pubkey": None, "allowed_ips": None, "actual_ip": None}
                first_line_of_block = True
            else:
                current = None
                first_line_of_block = False
            continue
        if current is None:
            continue
        if line.startswith("#"):
            comment = line.lstrip("#").strip()
            if first_line_of_block:
                current["name"] = comment or None
            else:
                m = PEER_IP_COMMENT_RE.match(comment)
                if m:
                    current["actual_ip"] = m.group(1)
            first_line_of_block = False
            continue
        first_line_of_block = False
        if line.lower().startswith("publickey"):
            current["pubkey"] = line.partition("=")[2].strip()
        elif line.lower().startswith("allowedips"):
            current["allowed_ips"] = line.partition("=")[2].strip()
    if current is not None:
        peers.append(current)
    return peers


def peer_own_ip(peer: dict):
    """Ermittelt die tatsaechliche eigene Tunnel-IP eines Peer-Eintrags.

    Nimmt bevorzugt die erste Adresse aus AllowedIPs - das ist bei einem
    gewoehnlichen Peer (AllowedIPs = eigene-ip/32, oder z.B. eigene-ip/24)
    korrekt UND die tatsaechlich vom Kernel fuers Routing benutzte, damit per
    Definition verlaessliche Angabe. Nur wenn die geschriebene Adresse selbst
    die Netzwerk-Adresse einer breiteren CIDR ist (z.B. AllowedIPs =
    10.250.0.0/24 bei einem Admin-Rechner mit weiterreichendem Zugriff) UND
    steckt darin KEINE Information ueber die tatsaechliche eigene IP - dann,
    und nur dann, zaehlt ersatzweise eine explizite "#IP: x.x.x.x"-
    Kommentarzeile (siehe fetch_wg_peers_from_config()). Ohne verwertbare
    AllowedIPs-Angabe und ohne Kommentar gibt es None zurueck statt zu raten.

    Bewusst NICHT umgekehrt (Kommentar immer bevorzugen, AllowedIPs nur als
    Fallback): in Produktion aufgetreten, dass ein "#IP:"-Kommentar versehentlich
    den WireGuard-*Endpoint* (die oeffentliche Internet-Adresse des Peers)
    statt dessen Tunnel-IP enthielt, waehrend AllowedIPs = <richtige-ip>/32
    bereits eindeutig und korrekt war - mit "Kommentar gewinnt immer" haette
    dieser Tippfehler eine an sich verlaessliche Angabe stillschweigend
    ueberschrieben. Ein "#IP:"-Kommentar, der nicht fuer den mehrdeutigen Fall
    gebraucht wird, hat so keine Chance, eine bereits eindeutige AllowedIPs-
    Angabe zu verfaelschen.
    """
    first_allowed = (peer.get("allowed_ips") or "").split(",")[0].strip()
    if first_allowed:
        host_ip = first_allowed.split("/")[0]
        try:
            net = ipaddress.ip_network(first_allowed, strict=False)
        except ValueError:
            net = None
        if net is None or net.num_addresses == 1 or host_ip != str(net.network_address):
            return host_ip
    return peer.get("actual_ip") or None


def peer_lookup_maps():
    """Baut pubkey->Name und ip->Name aus der WireGuard-Config des Ziels.

    Fehlt der Namens-Kommentar fuer einen Peer, wird er einfach ausgelassen
    (Aufrufer fallen dann auf IP/Pubkey als Anzeige zurueck).
    """
    pubkey_to_name = {}
    ip_to_name = {}
    for peer in fetch_wg_peers_from_config():
        name = peer.get("name")
        if not name:
            continue
        if peer.get("pubkey"):
            pubkey_to_name[peer["pubkey"]] = name
        ip = peer_own_ip(peer)
        if ip:
            ip_to_name[ip] = name
    return pubkey_to_name, ip_to_name


def peer_managed_networks(peer: dict, own_ip: str, wg_network=None) -> list:
    """Extrahiert aus AllowedIPs die Netze, die dieser Peer zusaetzlich zu
    seiner eigenen Tunnel-IP verwaltet - typischerweise das LAN hinter einem
    MikroTik-Router. Schliesst die eigene /32-Adresse sowie (falls
    `wg_network` uebergeben, ein ipaddress.ip_network des Mesh-Subnetzes)
    jedes Netz innerhalb des Mesh-Subnetzes aus (das waere weiterreichender
    Mesh-Zugriff wie bei einem Admin-Rechner, kein externes LAN).
    """
    allowed_ips = peer.get("allowed_ips") or ""
    managed = []
    for raw in allowed_ips.split(","):
        raw = raw.strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.num_addresses == 1 and str(net.network_address) == own_ip:
            continue
        if wg_network is not None and net.subnet_of(wg_network):
            continue
        managed.append(str(net))
    return managed


def fetch_wg_interface_info():
    """Liest [Interface]-Werte (Address, ListenPort) aus der Config des Ziels."""
    ok, out = run_on_target(f"cat /etc/wireguard/{config.TARGET_WG_INTERFACE}.conf 2>/dev/null")
    if not ok or not out.strip():
        return {}
    info = {}
    in_interface = False
    for raw_line in out.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("["):
            in_interface = line.lower() == "[interface]"
            continue
        if not in_interface:
            continue
        if line.lower().startswith("address"):
            info["address"] = line.partition("=")[2].strip()
        elif line.lower().startswith("listenport"):
            info["listen_port"] = line.partition("=")[2].strip()
    return info


def set_peer_allowed_ips(pubkey: str, allowed_ips_csv: str):
    """Setzt die AllowedIPs eines bereits bestehenden Peers live (`wg set`)
    UND dauerhaft in der Server-Config.

    Anders als provisioning.register_peer_on_target() (das nur einen NEUEN
    [Peer]-Block anhaengt) muss hier die AllowedIPs-Zeile innerhalb eines
    bereits bestehenden Blocks ERSETZT werden, ohne andere Peers oder Zeilen
    zu beruehren. Dafuer per awk den Block anhand des PublicKey identifizieren
    und nur dessen AllowedIPs-Zeile austauschen, dann atomar zurueckschreiben
    (Schreiben in eine Tempdatei + mv, kein Risiko einer halb geschriebenen
    Config bei einem Abbruch mitten im Schreiben).

    pubkey muss bereits validiert sein (validate_wg_pubkey), allowed_ips_csv
    eine Komma-Liste bereits validierter CIDRs (siehe networks.py) - beides
    landet direkt in einem per SSH oder lokal ausgefuehrten Bash/awk-Script;
    Base64-Zeichen und IP/CIDR-Zeichen enthalten kein Single-Quote, daher
    sicher in einfache Anfuehrungszeichen einbettbar.
    """
    iface = config.TARGET_WG_INTERFACE
    script = (
        "set -e\n"
        f"wg set {iface} peer {pubkey} allowed-ips {allowed_ips_csv}\n"
        f"CONF=/etc/wireguard/{iface}.conf\n"
        f"awk -v pubkey='{pubkey}' -v newip='{allowed_ips_csv}' '\n"
        "BEGIN { inblock = 0; inpeer = 0 }\n"
        "/^\\[Peer\\]/ { inblock = 1; inpeer = 0 }\n"
        "{\n"
        '  if (inblock && index($0, "PublicKey = " pubkey) > 0) { inpeer = 1 }\n'
        '  if (inpeer && $0 ~ /^AllowedIPs = /) { print "AllowedIPs = " newip; next }\n'
        "  print\n"
        "}\n"
        "' \"$CONF\" > \"$CONF.tmp\" && mv \"$CONF.tmp\" \"$CONF\"\n"
    )
    return run_on_target(script)
