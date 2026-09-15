import hmac
import ipaddress
import json
import math
import os
import re
import sqlite3
import subprocess
import datetime

from flask import Flask, Response, g, render_template, request, redirect, url_for, flash

DB_PATH = "/data/db/wgacl.db"
SSH_KEY = "/data/ssh/id_ed25519"
SSH_CONTROL_DIR = os.path.dirname(SSH_KEY)

ISURFER_WG_IP = os.environ.get("ISURFER_WG_IP", "10.250.0.1")
ISURFER_SSH_USER = os.environ.get("ISURFER_SSH_USER", "root")
TARGET_WG_INTERFACE = os.environ.get("TARGET_WG_INTERFACE", "wg0")

EXEC_MODE = os.environ.get("EXEC_MODE", "ssh").strip().lower()
if EXEC_MODE not in ("ssh", "local"):
    print(f"[app] WARNUNG: unbekannter EXEC_MODE={EXEC_MODE!r} - falle zurueck auf 'ssh'.")
    EXEC_MODE = "ssh"
print(f"[app] Ausfuehrungsmodus: {EXEC_MODE}")

ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
if not ADMIN_USER or not ADMIN_PASSWORD:
    print(
        "[app] WARNUNG: ADMIN_USER/ADMIN_PASSWORD nicht gesetzt - "
        "die Web-UI ist ohne Anmeldung erreichbar (siehe README/.env.example)."
    )

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

VALID_PROTOCOLS = {"tcp", "udp", "all"}
SERVICE_NAME_RE = re.compile(r"^[A-Za-z0-9 _.\-()]{1,64}$")

BUILTIN_SERVICES = [
    # name, protocol, port  (port=None -> alle Ports)
    ("SSH", "tcp", 22),
    ("RDP", "tcp", 3389),
    ("HTTPS-Alt (8443)", "tcp", 8443),
    ("PostgreSQL", "tcp", 5432),
    ("Proxmox VE", "tcp", 8006),
    ("HTTP", "tcp", 80),
    ("HTTPS", "tcp", 443),
    ("Alle Ports", "all", None),
]


@app.before_request
def require_basic_auth():
    if not ADMIN_USER or not ADMIN_PASSWORD:
        return None
    if request.endpoint == "static":
        return None
    auth = request.authorization
    if (
        auth
        and hmac.compare_digest(auth.username or "", ADMIN_USER)
        and hmac.compare_digest(auth.password or "", ADMIN_PASSWORD)
    ):
        return None
    return Response(
        "Anmeldung erforderlich.",
        401,
        {"WWW-Authenticate": 'Basic realm="WireGuard ACL Manager"'},
    )


_db_ready = False


def get_db():
    global _db_ready
    if not _db_ready:
        init_db()
        _db_ready = True
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            wg_ip TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL,
            restricted INTEGER NOT NULL DEFAULT 1,
            notes TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            protocol TEXT NOT NULL,
            port INTEGER,
            is_builtin INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            dest_ip TEXT NOT NULL,
            service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS apply_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            timestamp TEXT NOT NULL,
            success INTEGER NOT NULL,
            output TEXT
        );
        """
    )
    cur = db.execute("SELECT COUNT(*) FROM services")
    if cur.fetchone()[0] == 0:
        for name, proto, port in BUILTIN_SERVICES:
            db.execute(
                "INSERT INTO services (name, protocol, port, is_builtin) VALUES (?, ?, ?, 1)",
                (name, proto, port),
            )
    db.commit()
    db.close()


def detect_hook_chain() -> str:
    """Ermittelt, wohin die Client-Chains eingehaengt werden sollen.

    Server mit Docker (wie isurfer.de) haben eine DOCKER-USER-Chain, die vor
    Docker's eigener FORWARD-Logik ausgewertet wird - dort ist der richtige
    Ort fuer eigene Regeln, weil Docker die FORWARD-Policy sonst ueberschreibt.
    Server ohne Docker haben diese Chain nicht; dort wird direkt oben in
    FORWARD eingehaengt.
    """
    ok, _ = run_on_target("iptables -L DOCKER-USER -n >/dev/null 2>&1")
    return "DOCKER-USER" if ok else "FORWARD"


def check_ip_forward():
    ok, out = run_on_target("cat /proc/sys/net/ipv4/ip_forward")
    if not ok:
        return None
    return out.strip() == "1"


def chain_name(ip: str) -> str:
    return "WGACL_" + ip.replace(".", "_")


def chain_name_to_ip(chain: str) -> str:
    """Kehrt chain_name() um (nur fuer IPv4-Adressen verlaesslich)."""
    return chain[len("WGACL_"):].replace("_", ".")


def validate_dest_ip(dest_ip: str):
    """Normalisiert und validiert eine Ziel-IP/CIDR-Eingabe.

    Gibt "any" oder eine gueltige IP/CIDR zurueck, sonst None. Der Rueckgabewert
    landet unvalidiert in einem per SSH ausgefuehrten Bash-Script
    (build_apply_script) - ohne diese Pruefung waere das ein Einfallstor fuer
    Command-Injection ueber das Ziel-IP-Formularfeld.
    """
    dest = dest_ip.strip()
    if dest.lower() in ("any", "0.0.0.0/0", ""):
        return "any"
    try:
        ipaddress.ip_network(dest, strict=False)
    except ValueError:
        return None
    return dest


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
    if EXEC_MODE == "local":
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
                "-i", SSH_KEY,
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=8",
                # Verbindung zwischen mehreren run_on_target()-Aufrufen (z.B.
                # bei "Alle anwenden" fuer viele Clients) wiederverwenden
                # statt jedes Mal neu aufzubauen.
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={SSH_CONTROL_DIR}/cm-%r@%h:%p",
                "-o", "ControlPersist=60s",
                f"{ISURFER_SSH_USER}@{ISURFER_WG_IP}",
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


def build_apply_script(client_ip: str, rules: list, hook_chain: str) -> str:
    """Baut das idempotente iptables-Script fuer einen einzelnen Client."""
    chain = chain_name(client_ip)
    iface = TARGET_WG_INTERFACE
    lines = [
        "set -e",
        f'iptables -N {chain} 2>/dev/null || true',
        f'iptables -F {chain}',
    ]
    for r in rules:
        dest = r["dest_ip"].strip()
        proto = r["protocol"]
        port = r["port"]

        dest_part = "" if dest.lower() in ("any", "0.0.0.0/0", "") else f"-d {dest} "
        if proto == "all" or port is None:
            proto_part = ""
        else:
            proto_part = f"-p {proto} --dport {port} "
        lines.append(f'iptables -A {chain} {dest_part}{proto_part}-j ACCEPT'.replace("  ", " "))

    lines.append(f'iptables -A {chain} -j DROP')
    lines.append(
        f'iptables -C {hook_chain} -i {iface} -o {iface} -s {client_ip} -j {chain} 2>/dev/null '
        f'|| iptables -I {hook_chain} -i {iface} -o {iface} -s {client_ip} -j {chain}'
    )
    lines.append(
        'command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save '
        '|| echo "HINWEIS: netfilter-persistent nicht gefunden - Regeln ueberleben KEINEN Neustart. '
        'Manuell persistieren, z.B. mit iptables-save."'
    )
    return "\n".join(lines) + "\n"


def build_remove_script(client_ip: str, hook_chain: str) -> str:
    chain = chain_name(client_ip)
    iface = TARGET_WG_INTERFACE
    return (
        "set -e\n"
        f'iptables -D {hook_chain} -i {iface} -o {iface} -s {client_ip} -j {chain} 2>/dev/null || true\n'
        f'iptables -F {chain} 2>/dev/null || true\n'
        f'iptables -X {chain} 2>/dev/null || true\n'
        'command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save || true\n'
    )


def log_apply(db, client_id, success, output):
    db.execute(
        "INSERT INTO apply_log (client_id, timestamp, success, output) VALUES (?, ?, ?, ?)",
        (client_id, datetime.datetime.utcnow().isoformat(), int(success), output),
    )
    db.commit()


def apply_client(db, client):
    hook_chain = detect_hook_chain()
    if not client["restricted"]:
        ok, out = run_on_target(build_remove_script(client["wg_ip"], hook_chain))
        log_apply(db, client["id"], ok, out)
        return ok, out

    rules = db.execute(
        """
        SELECT r.dest_ip, s.protocol, s.port
        FROM rules r JOIN services s ON r.service_id = s.id
        WHERE r.client_id = ?
        """,
        (client["id"],),
    ).fetchall()
    script = build_apply_script(client["wg_ip"], rules, hook_chain)
    ok, out = run_on_target(script)
    log_apply(db, client["id"], ok, out)
    return ok, out


def fetch_wg_status():
    ok, out = run_on_target(f"wg show {TARGET_WG_INTERFACE} dump")
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


def list_remote_wgacl_chains():
    """Listet alle WGACL_*-Chains auf dem Zielserver auf (ok, chains_oder_fehlertext)."""
    ok, out = run_on_target(
        "iptables-save 2>/dev/null | grep -oE '^:WGACL_[A-Za-z0-9_]+' | sed 's/^://' | sort -u"
    )
    if not ok:
        return False, out
    return True, [c for c in out.split() if c]


def fetch_wg_peers_from_config():
    """Liest die WireGuard-Config auf dem Ziel und extrahiert je Peer Name,
    PublicKey und AllowedIPs.

    Namenskonvention: die erste Zeile direkt unter [Peer] ist ein Kommentar
    mit dem Anzeigenamen der Verbindung, z.B.:

        [Peer]
        #Buero-Router
        PublicKey = ...
        AllowedIPs = 10.250.0.5/32

    Gibt eine Liste von dicts {"name", "pubkey", "allowed_ips"} zurueck
    (leere Liste, falls die Config nicht lesbar ist).
    """
    ok, out = run_on_target(f"cat /etc/wireguard/{TARGET_WG_INTERFACE}.conf 2>/dev/null")
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
                current = {"name": None, "pubkey": None, "allowed_ips": None}
                first_line_of_block = True
            else:
                current = None
                first_line_of_block = False
            continue
        if current is None:
            continue
        if first_line_of_block:
            if line.startswith("#"):
                current["name"] = line.lstrip("#").strip() or None
            first_line_of_block = False
        if line.lower().startswith("publickey"):
            current["pubkey"] = line.partition("=")[2].strip()
        elif line.lower().startswith("allowedips"):
            current["allowed_ips"] = line.partition("=")[2].strip()
    if current is not None:
        peers.append(current)
    return peers


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
        first_allowed = (peer.get("allowed_ips") or "").split(",")[0].strip()
        ip = first_allowed.split("/")[0] if first_allowed else None
        if ip:
            ip_to_name[ip] = name
    return pubkey_to_name, ip_to_name


def import_peers_from_config(db):
    """Legt fuer alle Peers aus der WireGuard-Config, die noch kein Client in
    dieser App sind, einen neuen Client-Datensatz an - als "eingeschraenkt"
    und OHNE Regeln (derselbe Default wie beim manuellen "Client hinzufuegen").

    Bewusst KEINE Annahme ueber die tatsaechlichen Zugriffsrechte: was ein
    Peer aktuell darf, haengt von der real konfigurierten Firewall ab (siehe
    "Firewall-Regeln (Ist-Zustand)" auf der Wartungsseite) und nicht von
    einer pauschalen Mesh-Policy. Reiner DB-Abgleich, es wird nichts auf der
    Firewall veraendert (kein apply_client()-Aufruf) - erst ein spaeteres
    "Anwenden" fuer diesen Client wirkt sich tatsaechlich aus, und OHNE
    zuvor eingetragene Regeln wuerde das den Peer von allem abschneiden.

    Bestehende Clients werden nicht angefasst. Gibt (importiert, uebersprungen)
    zurueck.
    """
    existing_ips = {row["wg_ip"] for row in db.execute("SELECT wg_ip FROM clients").fetchall()}
    imported = 0
    skipped = 0
    for peer in fetch_wg_peers_from_config():
        first_allowed = (peer.get("allowed_ips") or "").split(",")[0].strip()
        ip = first_allowed.split("/")[0] if first_allowed else None
        if not ip:
            continue
        if ip in existing_ips:
            skipped += 1
            continue
        label = peer.get("name") or ip
        db.execute(
            "INSERT INTO clients (wg_ip, label, restricted) VALUES (?, ?, 1)",
            (ip, label),
        )
        existing_ips.add(ip)
        imported += 1
    db.commit()
    return imported, skipped


IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\b")


def annotate_ips(text: str, ip_labels: dict) -> str:
    """Haengt an bekannte IPv4-Adressen in einem Text den Peer-Namen an."""
    def repl(m):
        name = ip_labels.get(m.group(1))
        return m.group(0) + (f" ({name})" if name else "")
    return IPV4_RE.sub(repl, text)


def parse_iptables_rules(rule_text: str):
    """Bestes-effort-Parsing von 'iptables -S <chain>'-Zeilen.

    Deckt einfache -s/-d/-p/--dport/-j-Kombinationen ab, wie sie diese App
    selbst generiert und wie viele von Hand geschriebene Policy-Regeln
    aussehen. Zeilen mit Negation (!) oder zusaetzlichen Modulen (-m ...)
    werden bewusst NICHT als "einfach" interpretiert - das koennte die
    tatsaechliche Bedeutung verfaelschen. Fuer die gibt es weiterhin den
    Rohtext zum manuellen Nachlesen.
    """
    rules = []
    for line in rule_text.splitlines():
        line = line.strip()
        if not line.startswith("-A"):
            continue
        m_src = re.search(r"(?<!\S)-s\s+(\S+)", line)
        m_dst = re.search(r"(?<!\S)-d\s+(\S+)", line)
        m_proto = re.search(r"(?<!\S)-p\s+(\S+)", line)
        m_port = re.search(r"--dport\s+(\S+)", line)
        m_target = re.search(r"(?<!\S)-j\s+(\S+)", line)
        has_caveat = bool(re.search(r"(?<!\S)(!|-m\s)", line))
        rules.append({
            "raw": line,
            "src": m_src.group(1) if m_src else None,
            "dst": m_dst.group(1) if m_dst else None,
            "proto": m_proto.group(1) if m_proto else None,
            "port": m_port.group(1) if m_port else None,
            "target": m_target.group(1) if m_target else None,
            "simple": bool(m_target) and not has_caveat,
        })
    return rules


def build_ip_label_map(db):
    """IP -> Anzeigename, aus WireGuard-Config-Kommentaren + Client-Bezeichnungen."""
    _, ip_to_name = peer_lookup_maps()
    labels = dict(ip_to_name)
    for c in db.execute("SELECT wg_ip, label FROM clients").fetchall():
        labels.setdefault(c["wg_ip"], c["label"])
    return labels


# --------------------------------------------------------------------------
# Routen
# --------------------------------------------------------------------------

@app.route("/")
def index():
    db = get_db()
    clients = db.execute("SELECT * FROM clients ORDER BY wg_ip").fetchall()
    rules = db.execute(
        """
        SELECT r.id, r.client_id, r.dest_ip, s.name AS service_name,
               s.protocol, s.port
        FROM rules r JOIN services s ON r.service_id = s.id
        ORDER BY r.dest_ip
        """
    ).fetchall()
    rules_by_client = {}
    for r in rules:
        rules_by_client.setdefault(r["client_id"], []).append(r)

    peers, wg_error = fetch_wg_status()
    services_flat = db.execute("SELECT * FROM services ORDER BY is_builtin DESC, name").fetchall()
    hook_chain = detect_hook_chain() if wg_error is None else None
    ip_forward = check_ip_forward() if wg_error is None else None

    if peers:
        pubkey_to_name, _ = peer_lookup_maps()
        for p in peers:
            p["name"] = pubkey_to_name.get(p["pubkey"], "")

    return render_template(
        "index.html",
        clients=clients,
        rules_by_client=rules_by_client,
        peers=peers,
        wg_error=wg_error,
        services_flat=services_flat,
        hook_chain=hook_chain,
        ip_forward=ip_forward,
        wg_interface=TARGET_WG_INTERFACE,
    )


@app.route("/clients/import", methods=["POST"])
def import_peers():
    db = get_db()
    imported, skipped = import_peers_from_config(db)
    if imported:
        flash(
            f"{imported} Peer(s) aus der WireGuard-Config importiert (eingeschraenkt, ohne Regeln - "
            f"wie beim manuellen Hinzufuegen). Zugriffsrechte bitte anhand der tatsaechlichen Firewall-Regeln "
            f"('Wartung' -> 'Firewall-Regeln') nachtragen, bevor du 'Anwenden' klickst. "
            f"{skipped} bereits vorhanden.",
            "success",
        )
    else:
        flash(f"Keine neuen Peers gefunden ({skipped} bereits vorhanden, oder Config nicht lesbar).", "success")
    return redirect(url_for("index"))


@app.route("/clients/add", methods=["POST"])
def add_client():
    db = get_db()
    wg_ip = request.form["wg_ip"].strip()
    label = request.form["label"].strip()
    restricted = 1 if request.form.get("restricted") == "on" else 0
    try:
        db.execute(
            "INSERT INTO clients (wg_ip, label, restricted) VALUES (?, ?, ?)",
            (wg_ip, label, restricted),
        )
        db.commit()
        flash(f"Client {label} ({wg_ip}) hinzugefuegt.", "success")
    except sqlite3.IntegrityError:
        flash(f"Ein Client mit IP {wg_ip} existiert bereits.", "error")
    return redirect(url_for("index"))


@app.route("/clients/<int:client_id>/toggle", methods=["POST"])
def toggle_client(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("index"))
    new_val = 0 if client["restricted"] else 1
    db.execute("UPDATE clients SET restricted = ? WHERE id = ?", (new_val, client_id))
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = apply_client(db, client)
    if ok:
        flash(f"{client['label']}: Einschraenkung {'aktiviert' if new_val else 'deaktiviert'} und angewendet.", "success")
    else:
        flash(f"{client['label']}: Aenderung gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("index"))


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
def delete_client(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if client:
        hook_chain = detect_hook_chain()
        run_on_target(build_remove_script(client["wg_ip"], hook_chain))
        db.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        db.commit()
        flash(f"Client {client['label']} entfernt, Firewall-Regeln zurueckgebaut.", "success")
    return redirect(url_for("index"))


@app.route("/rules/add", methods=["POST"])
def add_rule():
    db = get_db()
    client_id = int(request.form["client_id"])
    dest_ip_raw = request.form["dest_ip"].strip()
    service_id = int(request.form["service_id"])
    dest_ip = validate_dest_ip(dest_ip_raw)
    if dest_ip is None:
        flash(f"Ungueltige Ziel-IP/CIDR: {dest_ip_raw!r}", "error")
        return redirect(url_for("index"))
    db.execute(
        "INSERT INTO rules (client_id, dest_ip, service_id, created_at) VALUES (?, ?, ?, ?)",
        (client_id, dest_ip, service_id, datetime.datetime.utcnow().isoformat()),
    )
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = apply_client(db, client)
    if ok:
        flash("Regel hinzugefuegt und angewendet.", "success")
    else:
        flash(f"Regel gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("index"))


@app.route("/rules/<int:rule_id>/delete", methods=["POST"])
def delete_rule(rule_id):
    db = get_db()
    rule = db.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
    if not rule:
        return redirect(url_for("index"))
    client_id = rule["client_id"]
    db.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
    db.commit()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    ok, out = apply_client(db, client)
    if ok:
        flash("Regel entfernt und angewendet.", "success")
    else:
        flash(f"Regel entfernt, aber Anwenden fehlgeschlagen: {out}", "error")
    return redirect(url_for("index"))


@app.route("/apply/<int:client_id>", methods=["POST"])
def apply_single(client_id):
    db = get_db()
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("index"))
    ok, out = apply_client(db, client)
    flash(f"{client['label']}: {'erfolgreich angewendet' if ok else 'Fehler: ' + out}",
          "success" if ok else "error")
    return redirect(url_for("index"))


@app.route("/apply_all", methods=["POST"])
def apply_all():
    db = get_db()
    clients = db.execute("SELECT * FROM clients").fetchall()
    errors = []
    for client in clients:
        ok, out = apply_client(db, client)
        if not ok:
            errors.append(f"{client['label']}: {out}")
    if errors:
        flash("Fehler bei: " + "; ".join(errors), "error")
    else:
        flash(f"Alle {len(clients)} Clients erfolgreich angewendet.", "success")
    return redirect(url_for("index"))


@app.route("/services")
def services():
    db = get_db()
    all_services = db.execute("SELECT * FROM services ORDER BY is_builtin DESC, name").fetchall()
    return render_template("services.html", services=all_services)


@app.route("/services/add", methods=["POST"])
def add_service():
    db = get_db()
    name = request.form["name"].strip()
    protocol = request.form["protocol"].strip().lower()
    port_raw = request.form.get("port", "").strip()

    if not SERVICE_NAME_RE.match(name):
        flash("Ungueltiger Dienstname (erlaubt: Buchstaben, Zahlen, Leerzeichen, . _ - ( )).", "error")
        return redirect(url_for("services"))
    if protocol not in VALID_PROTOCOLS:
        flash(f"Ungueltiges Protokoll: {protocol!r}", "error")
        return redirect(url_for("services"))

    port = None
    if port_raw:
        if not port_raw.isdigit() or not (1 <= int(port_raw) <= 65535):
            flash("Port muss eine Zahl zwischen 1 und 65535 sein.", "error")
            return redirect(url_for("services"))
        port = int(port_raw)
    if protocol == "all":
        port = None

    try:
        db.execute(
            "INSERT INTO services (name, protocol, port, is_builtin) VALUES (?, ?, ?, 0)",
            (name, protocol, port),
        )
        db.commit()
        flash(f"Dienst {name} hinzugefuegt.", "success")
    except sqlite3.IntegrityError:
        flash(f"Ein Dienst namens {name} existiert bereits.", "error")
    return redirect(url_for("services"))


@app.route("/services/<int:service_id>/delete", methods=["POST"])
def delete_service(service_id):
    db = get_db()
    service = db.execute("SELECT * FROM services WHERE id = ?", (service_id,)).fetchone()
    if service and service["is_builtin"]:
        flash("Standarddienste koennen nicht geloescht werden.", "error")
    elif service:
        in_use = db.execute("SELECT COUNT(*) c FROM rules WHERE service_id = ?", (service_id,)).fetchone()["c"]
        if in_use:
            flash(f"Dienst wird noch in {in_use} Regel(n) verwendet - erst dort entfernen.", "error")
        else:
            db.execute("DELETE FROM services WHERE id = ?", (service_id,))
            db.commit()
            flash("Dienst geloescht.", "success")
    return redirect(url_for("services"))


@app.route("/maintenance")
def maintenance():
    db = get_db()
    clients = db.execute("SELECT wg_ip FROM clients").fetchall()
    known_chains = {chain_name(c["wg_ip"]) for c in clients}
    ok, result = list_remote_wgacl_chains()
    orphaned = []
    remote_error = None
    if ok:
        orphaned = sorted(c for c in result if c not in known_chains)
    else:
        remote_error = result

    ip_labels = build_ip_label_map(db)
    firewall_sections = []
    for chain in ("DOCKER-USER", "FORWARD"):
        f_ok, f_out = run_on_target(f"iptables -S {chain} 2>&1")
        if not f_ok:
            firewall_sections.append({"chain": chain, "ok": False, "error": f_out})
            continue
        rules = parse_iptables_rules(f_out)
        for r in rules:
            r["src_label"] = ip_labels.get((r["src"] or "").split("/")[0], r["src"] or "*")
            r["dst_label"] = ip_labels.get((r["dst"] or "").split("/")[0], r["dst"] or "*")
        firewall_sections.append({
            "chain": chain,
            "ok": True,
            "rules": rules,
            "raw": annotate_ips(f_out, ip_labels),
        })

    return render_template(
        "maintenance.html",
        orphaned=orphaned,
        remote_error=remote_error,
        firewall_sections=firewall_sections,
    )


@app.route("/maintenance/cleanup", methods=["POST"])
def cleanup_orphaned_chains():
    db = get_db()
    clients = db.execute("SELECT wg_ip FROM clients").fetchall()
    known_chains = {chain_name(c["wg_ip"]) for c in clients}
    ok, result = list_remote_wgacl_chains()
    if not ok:
        flash(f"Konnte verwaiste Chains nicht ermitteln: {result}", "error")
        return redirect(url_for("maintenance"))

    hook_chain = detect_hook_chain()
    removed, errors = [], []
    for chain in result:
        if chain in known_chains:
            continue
        ip_guess = chain_name_to_ip(chain)
        rok, rout = run_on_target(build_remove_script(ip_guess, hook_chain))
        (removed if rok else errors).append(chain)

    if removed:
        flash(f"{len(removed)} verwaiste Chain(s) entfernt: {', '.join(removed)}", "success")
    if errors:
        flash(f"Fehler beim Entfernen von: {', '.join(errors)}", "error")
    if not removed and not errors:
        flash("Keine verwaisten Chains gefunden.", "success")
    return redirect(url_for("maintenance"))


def get_all_ports_service_id(db):
    row = db.execute(
        "SELECT id FROM services WHERE protocol = 'all' AND port IS NULL LIMIT 1"
    ).fetchone()
    return row["id"] if row else None


def diff_target_sets(existing: set, desired: set):
    """Reine Diff-Logik fuer die Berechtigungsmatrix: (hinzuzufuegen, zu entfernen)."""
    return desired - existing, existing - desired


def build_netzplan_data(db):
    """Baut Knoten (Peers) und Kanten (Regeln) fuer den Netzplan.

    Knoten: alle erfassten Clients + alle Ziel-IPs aus Regeln (inkl. "any"
    als eigener Pseudo-Knoten "Internet / alle Ziele"), kreisfoermig
    angeordnet. Kanten: eine je (Quelle, Ziel)-Paar, mit allen dafuer
    erlaubten Diensten zusammengefasst (fuer den Hover-Tooltip). Fuer
    uneingeschraenkte Clients werden keine Kanten gezeichnet (sie duerfen
    ohnehin ueberallhin) - sie werden stattdessen optisch hervorgehoben.
    """
    clients = db.execute("SELECT * FROM clients ORDER BY wg_ip").fetchall()
    rules = db.execute(
        """
        SELECT c.wg_ip AS src_ip, r.dest_ip, s.name AS service_name
        FROM rules r
        JOIN clients c ON r.client_id = c.id
        JOIN services s ON r.service_id = s.id
        """
    ).fetchall()

    _, ip_to_name = peer_lookup_maps()
    client_by_ip = {c["wg_ip"]: c for c in clients}

    def label_for(ip):
        if ip in client_by_ip:
            return client_by_ip[ip]["label"]
        return ip_to_name.get(ip, ip)

    ordered_ips = [c["wg_ip"] for c in clients]
    seen_ips = set(ordered_ips)
    show_internet_node = False
    edge_map = {}
    for r in rules:
        dest = r["dest_ip"]
        if dest == "any":
            show_internet_node = True
            dest_key = "__any__"
        else:
            dest_key = dest
            if dest_key not in seen_ips:
                seen_ips.add(dest_key)
                ordered_ips.append(dest_key)
        edge_map.setdefault((r["src_ip"], dest_key), []).append(r["service_name"])

    if show_internet_node:
        ordered_ips.append("__any__")

    n = len(ordered_ips)
    cx, cy, radius = 320, 300, 235
    positions = {}
    nodes = []
    for i, ip in enumerate(ordered_ips):
        angle = (2 * math.pi * i / n) - (math.pi / 2) if n else 0
        x = cx + radius * math.cos(angle)
        y = cy + radius * math.sin(angle)
        client = client_by_ip.get(ip)
        label = "Internet / alle Ziele" if ip == "__any__" else label_for(ip)
        positions[ip] = (x, y)
        nodes.append({
            "ip": ip,
            "x": round(x, 1),
            "y": round(y, 1),
            "label": label,
            "unrestricted": bool(client and not client["restricted"]),
            "is_client": ip in client_by_ip,
        })

    edges = []
    for (src_ip, dest_key), services in edge_map.items():
        if src_ip not in positions or dest_key not in positions:
            continue
        x1, y1 = positions[src_ip]
        x2, y2 = positions[dest_key]
        edges.append({
            "x1": round(x1, 1), "y1": round(y1, 1),
            "x2": round(x2, 1), "y2": round(y2, 1),
            "src_label": label_for(src_ip),
            "dest_label": "Internet / alle Ziele" if dest_key == "__any__" else label_for(dest_key),
            "services": ", ".join(sorted(set(services))),
        })

    return nodes, edges


@app.route("/netzplan")
def netzplan():
    db = get_db()
    nodes, edges = build_netzplan_data(db)

    restricted_clients = db.execute(
        "SELECT * FROM clients WHERE restricted = 1 ORDER BY label"
    ).fetchall()
    all_clients = db.execute("SELECT * FROM clients ORDER BY label").fetchall()

    _, ip_to_name = peer_lookup_maps()
    target_by_ip = {c["wg_ip"]: c["label"] for c in all_clients}
    for ip, name in ip_to_name.items():
        target_by_ip.setdefault(ip, name)
    all_targets = [{"ip": ip, "label": label} for ip, label in sorted(target_by_ip.items(), key=lambda kv: kv[1])]

    all_ports_service_id = get_all_ports_service_id(db)
    client_targets = {}
    if all_ports_service_id is not None:
        for c in restricted_clients:
            rows = db.execute(
                "SELECT dest_ip FROM rules WHERE client_id = ? AND service_id = ?",
                (c["id"], all_ports_service_id),
            ).fetchall()
            client_targets[c["id"]] = [row["dest_ip"] for row in rows]

    return render_template(
        "netzplan.html",
        nodes=nodes,
        edges=edges,
        restricted_clients=restricted_clients,
        all_clients_json=json.dumps([
            {"id": c["id"], "label": c["label"], "wg_ip": c["wg_ip"]} for c in restricted_clients
        ]),
        all_targets_json=json.dumps(all_targets),
        client_targets_json=json.dumps(client_targets),
    )


@app.route("/netzplan/permissions/set", methods=["POST"])
def set_full_access_targets():
    db = get_db()
    client_id = int(request.form["client_id"])
    client = db.execute("SELECT * FROM clients WHERE id = ?", (client_id,)).fetchone()
    if not client:
        flash("Client nicht gefunden.", "error")
        return redirect(url_for("netzplan"))
    if not client["restricted"]:
        flash(f"{client['label']} ist uneingeschraenkt - hat bereits Zugriff auf alles.", "error")
        return redirect(url_for("netzplan"))

    all_ports_service_id = get_all_ports_service_id(db)
    if all_ports_service_id is None:
        flash("Dienst 'Alle Ports' nicht gefunden - Datenbank inkonsistent.", "error")
        return redirect(url_for("netzplan"))

    desired = set()
    for raw_ip in request.form.getlist("targets"):
        ip = raw_ip.strip()
        if not ip or ip == client["wg_ip"]:
            continue
        if validate_dest_ip(ip) is None:
            flash(f"Ungueltiges Ziel ignoriert: {ip!r}", "error")
            continue
        desired.add(ip)

    existing_rows = db.execute(
        "SELECT id, dest_ip FROM rules WHERE client_id = ? AND service_id = ?",
        (client_id, all_ports_service_id),
    ).fetchall()
    existing_by_ip = {row["dest_ip"]: row["id"] for row in existing_rows}

    added, removed = diff_target_sets(set(existing_by_ip.keys()), desired)

    for ip in added:
        db.execute(
            "INSERT INTO rules (client_id, dest_ip, service_id, created_at) VALUES (?, ?, ?, ?)",
            (client_id, ip, all_ports_service_id, datetime.datetime.utcnow().isoformat()),
        )
    for ip in removed:
        db.execute("DELETE FROM rules WHERE id = ?", (existing_by_ip[ip],))
    if added or removed:
        db.commit()
        ok, out = apply_client(db, client)
        if ok:
            flash(
                f"{client['label']}: {len(added)} Ziel(e) hinzugefuegt, {len(removed)} entfernt, angewendet.",
                "success",
            )
        else:
            flash(f"{client['label']}: Aenderungen gespeichert, aber Anwenden fehlgeschlagen: {out}", "error")
    else:
        flash("Keine Aenderung.", "success")
    return redirect(url_for("netzplan"))


def reapply_all_on_startup():
    """Baut beim Start alle Client-Regeln aus der DB neu auf.

    Nur im lokalen Modus relevant: dort faellt der Container-(Neu-)Start
    typischerweise mit einem Host-Reboot zusammen (restart: unless-stopped),
    und iptables-Regeln ueberleben einen Reboot nicht von selbst. Statt eine
    zusaetzliche netfilter-persistent-Abhaengigkeit zu brauchen, baut die App
    ihre eigenen WGACL_*-Chains einfach aus der SQLite-DB neu auf.
    """
    with app.app_context():
        db = get_db()
        clients = db.execute("SELECT * FROM clients").fetchall()
        for client in clients:
            apply_client(db, client)


if EXEC_MODE == "local":
    reapply_all_on_startup()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
