import os
import sqlite3
import subprocess
import datetime

from flask import Flask, g, render_template, request, redirect, url_for, flash

DB_PATH = "/data/db/wgacl.db"
SSH_KEY = "/data/ssh/id_ed25519"

ISURFER_WG_IP = os.environ.get("ISURFER_WG_IP", "10.250.0.1")
ISURFER_SSH_USER = os.environ.get("ISURFER_SSH_USER", "root")
TARGET_WG_INTERFACE = os.environ.get("TARGET_WG_INTERFACE", "wg0")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret-change-me")

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


def get_db():
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
    ok, _ = ssh_run("iptables -L DOCKER-USER -n >/dev/null 2>&1")
    return "DOCKER-USER" if ok else "FORWARD"


def check_ip_forward():
    ok, out = ssh_run("cat /proc/sys/net/ipv4/ip_forward")
    if not ok:
        return None
    return out.strip() == "1"


def chain_name(ip: str) -> str:
    return "WGACL_" + ip.replace(".", "_")


def ssh_run(script: str, timeout: int = 15):
    """Fuehrt ein Bash-Script auf dem Ziel-WG-Server per SSH aus (ueber den WG-Tunnel)."""
    try:
        result = subprocess.run(
            [
                "ssh",
                "-i", SSH_KEY,
                "-o", "StrictHostKeyChecking=accept-new",
                "-o", "ConnectTimeout=8",
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
        ok, out = ssh_run(build_remove_script(client["wg_ip"], hook_chain))
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
    ok, out = ssh_run(script)
    log_apply(db, client["id"], ok, out)
    return ok, out


def fetch_wg_status():
    ok, out = ssh_run(f"wg show {TARGET_WG_INTERFACE} dump")
    if not ok:
        return None, out
    peers = []
    for i, line in enumerate(out.strip().splitlines()):
        parts = line.split("\t")
        if i == 0:
            continue  # erste Zeile ist das Interface selbst
        if len(parts) >= 7:
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
        ssh_run(build_remove_script(client["wg_ip"], hook_chain))
        db.execute("DELETE FROM clients WHERE id = ?", (client_id,))
        db.commit()
        flash(f"Client {client['label']} entfernt, Firewall-Regeln zurueckgebaut.", "success")
    return redirect(url_for("index"))


@app.route("/rules/add", methods=["POST"])
def add_rule():
    db = get_db()
    client_id = int(request.form["client_id"])
    dest_ip = request.form["dest_ip"].strip()
    service_id = int(request.form["service_id"])
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
    protocol = request.form["protocol"].strip()
    port_raw = request.form.get("port", "").strip()
    port = int(port_raw) if port_raw else None
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


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=8080)
