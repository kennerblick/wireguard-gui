"""Anwendungslogik oberhalb von firewall.py/wireguard.py: was in der DB
steht in tatsaechliche iptables-Aenderungen uebersetzen (inkl. Aufloesen
von Gruppen-Regeln), Peers aus der Config importieren, Daten fuer den
Netzplan aufbereiten.
"""

import datetime
import ipaddress
import math

from . import config, firewall, networks, tags, wireguard


def log_apply(db, client_id, success, output):
    db.execute(
        "INSERT INTO apply_log (client_id, timestamp, success, output) VALUES (?, ?, ?, ?)",
        (client_id, datetime.datetime.utcnow().isoformat(), int(success), output),
    )
    db.commit()


def resolve_rule_targets(db, client_id, raw_rules):
    """Expandiert Gruppen-Regeln (dest_tag_id) zu konkreten Ziel-IPs.

    raw_rules: Zeilen mit dest_ip, dest_tag_id, protocol, port. Eine Regel
    hat entweder dest_ip (inkl. "any") ODER dest_tag_id gesetzt (dest_ip ist
    dann der Sentinel "", siehe db.run_migrations()-Docstring). Gibt eine
    flache Liste von {"dest_ip", "protocol", "port"} zurueck, wie sie
    firewall.build_apply_script() erwartet - eine Zeile pro konkretem Ziel;
    bei einer Gruppe eine Zeile je aktuellem Mitglied (der Client selbst
    wird ausgeschlossen), eine leere Gruppe ergibt keine Zeile.
    """
    resolved = []
    for r in raw_rules:
        if r["dest_tag_id"] is not None:
            for ip in tags.tag_member_ips(db, r["dest_tag_id"], exclude_client_id=client_id):
                resolved.append({"dest_ip": ip, "protocol": r["protocol"], "port": r["port"]})
        else:
            resolved.append({"dest_ip": r["dest_ip"], "protocol": r["protocol"], "port": r["port"]})
    return resolved


def apply_client(db, client):
    hook_chain = firewall.detect_hook_chain()
    if not client["restricted"]:
        ok, out = wireguard.run_on_target(firewall.build_remove_script(client["wg_ip"], hook_chain))
        log_apply(db, client["id"], ok, out)
        return ok, out

    raw_rules = db.execute(
        """
        SELECT r.dest_ip, r.dest_tag_id, s.protocol, s.port
        FROM rules r JOIN services s ON r.service_id = s.id
        WHERE r.client_id = ?
        """,
        (client["id"],),
    ).fetchall()
    rules = resolve_rule_targets(db, client["id"], raw_rules)
    script = firewall.build_apply_script(client["wg_ip"], rules, hook_chain)
    ok, out = wireguard.run_on_target(script)
    log_apply(db, client["id"], ok, out)
    return ok, out


def reapply_all_on_startup():
    """Baut beim Start alle Client-Regeln aus der DB neu auf.

    Nur im lokalen Modus relevant: dort faellt der Container-(Neu-)Start
    typischerweise mit einem Host-Reboot zusammen (restart: unless-stopped),
    und iptables-Regeln ueberleben einen Reboot nicht von selbst. Statt eine
    zusaetzliche netfilter-persistent-Abhaengigkeit zu brauchen, baut die App
    ihre eigenen WGACL_*-Chains einfach aus der SQLite-DB neu auf. Muss
    innerhalb eines app.app_context() aufgerufen werden (siehe __init__.py).
    """
    from . import db as db_module
    db = db_module.get_db()
    clients = db.execute("SELECT * FROM clients").fetchall()
    for client in clients:
        apply_client(db, client)


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

    Bestehende Clients werden nicht angefasst. Erkennt zusaetzlich fuer jeden
    neu importierten Peer verwaltete Netze (siehe
    wireguard.peer_managed_networks()) - Netze in AllowedIPs jenseits der
    eigenen Tunnel-IP und ausserhalb des Mesh-Subnetzes, typischerweise das
    LAN hinter einem MikroTik-Router - und uebernimmt sie direkt als
    Rule-Ziel-Vorschlag (networks.set_client_networks()). Das aendert nichts
    an der Firewall auf dem Server, nur an dieser App's eigener Datenhaltung.

    Peers, deren eigene IP sich nicht sicher ermitteln laesst (AllowedIPs
    deckt ein ganzes Subnetz ab, ohne dass eine explizite "#IP:"-
    Kommentarzeile die tatsaechliche Adresse nennt - siehe
    wireguard.peer_own_ip()), werden NICHT importiert und stattdessen in
    einer eigenen Liste gemeldet, statt versehentlich mit der Netzwerk-
    Adresse als (falscher) eigener IP angelegt zu werden - eine daraus
    gebaute Firewall-Regel wuerde nie den tatsaechlichen Traffic dieses
    Peers treffen.

    Gibt (importiert, uebersprungen, mehrdeutig) zurueck - mehrdeutig ist
    eine Liste von Anzeigenamen (Name-Kommentar oder Pubkey-Praefix) der
    nicht importierten Peers.
    """
    wg_network = None
    address = wireguard.fetch_wg_interface_info().get("address")
    if address:
        try:
            wg_network = ipaddress.ip_interface(address).network
        except ValueError:
            wg_network = None

    existing_ips = {row["wg_ip"] for row in db.execute("SELECT wg_ip FROM clients").fetchall()}
    imported = 0
    skipped = 0
    ambiguous = []
    for peer in wireguard.fetch_wg_peers_from_config():
        ip = wireguard.peer_own_ip(peer)
        if not ip:
            pubkey = peer.get("pubkey") or "?"
            ambiguous.append(peer.get("name") or f"{pubkey[:16]}...")
            continue
        if ip in existing_ips:
            skipped += 1
            continue
        label = peer.get("name") or ip
        cur = db.execute(
            "INSERT INTO clients (wg_ip, label, restricted) VALUES (?, ?, 1)",
            (ip, label),
        )
        managed = wireguard.peer_managed_networks(peer, ip, wg_network)
        if managed:
            networks.set_client_networks(db, cur.lastrowid, managed)
        existing_ips.add(ip)
        imported += 1
    db.commit()
    return imported, skipped, ambiguous


def build_ip_label_map(db):
    """IP/CIDR -> Anzeigename, aus WireGuard-Config-Kommentaren,
    Client-Bezeichnungen und verwalteten Netzen (LAN hinter einem Client,
    z.B. einem MikroTik-Router)."""
    _, ip_to_name = wireguard.peer_lookup_maps()
    labels = dict(ip_to_name)
    for c in db.execute("SELECT wg_ip, label FROM clients").fetchall():
        labels.setdefault(c["wg_ip"], c["label"])
    for row in networks.all_networks_with_client(db):
        labels.setdefault(row["cidr"], f"LAN hinter {row['client_label']}")
    return labels


def get_all_ports_service_id(db):
    row = db.execute(
        "SELECT id FROM services WHERE protocol = 'all' AND port IS NULL LIMIT 1"
    ).fetchone()
    return row["id"] if row else None


def diff_target_sets(existing: set, desired: set):
    """Reine Diff-Logik fuer die Berechtigungsmatrix: (hinzuzufuegen, zu entfernen)."""
    return desired - existing, existing - desired


def build_netzplan_data(db):
    """Baut Knoten (WG-Server, Peers, Gruppen) und Kanten (Regeln) fuer den
    Netzplan.

    Knoten: ein zentraler WG-Server-Knoten (der Tunnel-Endpunkt, ueber den
    aller Peer-zu-Peer-Verkehr laeuft) + alle erfassten Clients + alle
    Ziel-IPs aus IP-Regeln + ggf. "Internet / alle Ziele" fuer dest_ip ==
    "any" auf einem aeusseren Ring, sowie ein Pseudo-Knoten je referenziertem
    Tag ("Gruppe: <Name>") gebuendelt auf einem inneren Ring um den Server -
    das haelt Gruppen visuell zusammen statt sie zwischen den Peers verstreut
    darzustellen. Kanten: eine gestrichelte Tunnel-Kante vom Server zu jedem
    Client (reine Topologie, kein Hover-Text) plus eine ACL-Kante je (Quelle,
    Ziel)-Regel-Paar, mit allen dafuer erlaubten Diensten zusammengefasst
    (fuer den Hover-Tooltip). Gruppen-Regeln zeigen auf den Gruppen-Pseudo-
    Knoten statt auf jedes einzelne Mitglied - haelt den Graphen lesbar und
    aktuell (Mitgliedschaft kann sich unabhaengig von der Regel aendern).
    Fuer uneingeschraenkte Clients werden keine ACL-Kanten gezeichnet (sie
    duerfen ohnehin ueberallhin) - sie werden stattdessen optisch
    hervorgehoben.
    """
    clients = db.execute("SELECT * FROM clients ORDER BY wg_ip").fetchall()
    rules = db.execute(
        """
        SELECT c.wg_ip AS src_ip, r.dest_ip, r.dest_tag_id, t.name AS tag_name,
               s.name AS service_name
        FROM rules r
        JOIN clients c ON r.client_id = c.id
        JOIN services s ON r.service_id = s.id
        LEFT JOIN tags t ON t.id = r.dest_tag_id
        """
    ).fetchall()

    _, ip_to_name = wireguard.peer_lookup_maps()
    client_by_ip = {c["wg_ip"]: c for c in clients}

    def label_for(ip):
        if ip in client_by_ip:
            return client_by_ip[ip]["label"]
        return ip_to_name.get(ip, ip)

    ring_ips = [c["wg_ip"] for c in clients]
    seen_ips = set(ring_ips)
    group_keys = []
    pseudo_labels = {}
    show_internet_node = False
    edge_map = {}
    for r in rules:
        if r["dest_tag_id"] is not None:
            dest_key = f"__tag_{r['dest_tag_id']}__"
            pseudo_labels[dest_key] = f"Gruppe: {r['tag_name']}"
            if dest_key not in seen_ips:
                seen_ips.add(dest_key)
                group_keys.append(dest_key)
        elif r["dest_ip"] == "any":
            show_internet_node = True
            dest_key = "__any__"
            if dest_key not in seen_ips:
                seen_ips.add(dest_key)
                ring_ips.append(dest_key)
        else:
            dest_key = r["dest_ip"]
            if dest_key not in seen_ips:
                seen_ips.add(dest_key)
                ring_ips.append(dest_key)
        edge_map.setdefault((r["src_ip"], dest_key), []).append(r["service_name"])

    if show_internet_node and "__any__" not in seen_ips:
        ring_ips.append("__any__")
        seen_ips.add("__any__")

    cx, cy = 320, 300
    outer_radius = 235
    group_radius = 120
    positions = {}
    nodes = []

    server_key = "__server__"
    server_label = f"WG-Server ({config.WG_SERVER_TUNNEL_IP})"
    positions[server_key] = (cx, cy)
    nodes.append({
        "ip": server_key,
        "x": cx,
        "y": cy,
        "label": server_label,
        "unrestricted": False,
        "is_client": False,
        "is_group": False,
        "is_server": True,
    })

    n_outer = len(ring_ips)
    for i, ip in enumerate(ring_ips):
        angle = (2 * math.pi * i / n_outer) - (math.pi / 2) if n_outer else 0
        x = cx + outer_radius * math.cos(angle)
        y = cy + outer_radius * math.sin(angle)
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
            "is_group": False,
            "is_server": False,
        })

    n_group = len(group_keys)
    for i, key in enumerate(group_keys):
        angle = (2 * math.pi * i / n_group) - (math.pi / 2) if n_group else 0
        x = cx + group_radius * math.cos(angle)
        y = cy + group_radius * math.sin(angle)
        positions[key] = (x, y)
        nodes.append({
            "ip": key,
            "x": round(x, 1),
            "y": round(y, 1),
            "label": pseudo_labels[key],
            "unrestricted": False,
            "is_client": False,
            "is_group": True,
            "is_server": False,
        })

    edges = []
    for c in clients:
        if c["wg_ip"] not in positions:
            continue
        x1, y1 = positions[server_key]
        x2, y2 = positions[c["wg_ip"]]
        edges.append({
            "x1": round(x1, 1), "y1": round(y1, 1),
            "x2": round(x2, 1), "y2": round(y2, 1),
            "src_label": server_label,
            "dest_label": c["label"],
            "services": "VPN-Tunnel",
            "kind": "tunnel",
        })

    for (src_ip, dest_key), services in edge_map.items():
        if src_ip not in positions or dest_key not in positions:
            continue
        x1, y1 = positions[src_ip]
        x2, y2 = positions[dest_key]
        if dest_key == "__any__":
            dest_label = "Internet / alle Ziele"
        elif dest_key in pseudo_labels:
            dest_label = pseudo_labels[dest_key]
        else:
            dest_label = label_for(dest_key)
        edges.append({
            "x1": round(x1, 1), "y1": round(y1, 1),
            "x2": round(x2, 1), "y2": round(y2, 1),
            "src_label": label_for(src_ip),
            "dest_label": dest_label,
            "services": ", ".join(sorted(set(services))),
            "kind": "acl",
        })

    return nodes, edges
