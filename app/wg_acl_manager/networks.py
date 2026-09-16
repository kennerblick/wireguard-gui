"""Verwaltete Netze pro Client: LANs, die hinter einem Peer liegen (typischerweise
ein MikroTik-Router mit einem eigenen Netz dahinter) und ueber den Tunnel
erreichbar sein sollen - im Unterschied zur eigenen Tunnel-IP des Peers selbst.

Rein als Datenhaltung + Komfort gedacht:
- Als Rule-Ziel: eine Regel mit dest_ip = "192.168.88.0/24" funktioniert bereits
  heute unveraendert (validate_dest_ip()/build_apply_script() akzeptieren jede
  gueltige IP/CIDR) - hier geht es nur darum, dass ein Admin diese Netze nicht
  auswendig kennen/eintippen muss, sondern sie einmal je Client hinterlegt und
  danach im Regel-Formular als bekanntes Ziel vorgeschlagen bekommt.
- Fuer tatsaechliches Routing zu einem solchen Netz muss zusaetzlich der
  WireGuard-Server den Peer mit AllowedIPs inkl. dieses Netzes fuehren (sonst
  leitet der Kernel Pakete dorthin gar nicht erst zum Peer) - siehe
  provisioning.register_peer_on_target() (bei Neuanlage) und
  wireguard.set_peer_allowed_ips() (nachtraegliche Aenderung eines bestehenden
  Peers, genutzt von routes/networks.py).
"""

import ipaddress


def validate_network_cidr(raw: str):
    """Normalisiert/validiert eine einzelne Netz-Eingabe. Gibt die kanonische
    CIDR-Form oder None zurueck. Anders als firewall.validate_dest_ip() gibt es
    hier kein "any" - ein verwaltetes Netz muss ein konkretes Netz sein."""
    raw = raw.strip()
    if not raw:
        return None
    try:
        return str(ipaddress.ip_network(raw, strict=False))
    except ValueError:
        return None


def list_client_networks(db, client_id: int):
    return db.execute(
        "SELECT id, cidr FROM client_networks WHERE client_id = ? ORDER BY cidr",
        (client_id,),
    ).fetchall()


def set_client_networks(db, client_id: int, raw_lines):
    """Ersetzt komplett die Liste der von diesem Client verwalteten Netze.

    raw_lines: Iterable roher Text-Eingaben (z.B. Zeilen aus einem Textarea).
    Gibt die Liste der ungueltigen Eingaben zurueck (leer = alles uebernommen).
    Aktualisiert NICHT die AllowedIPs auf dem WireGuard-Server - das ist
    Aufgabe des Aufrufers (siehe routes/networks.py), da dafuer zusaetzlich
    der Peer live nachgeschlagen werden muss.
    """
    valid = []
    errors = []
    for raw in raw_lines:
        raw = raw.strip()
        if not raw:
            continue
        cidr = validate_network_cidr(raw)
        if cidr is None:
            errors.append(raw)
        else:
            valid.append(cidr)

    db.execute("DELETE FROM client_networks WHERE client_id = ?", (client_id,))
    for cidr in valid:
        db.execute(
            "INSERT OR IGNORE INTO client_networks (client_id, cidr) VALUES (?, ?)",
            (client_id, cidr),
        )
    db.commit()
    return errors


def all_networks_with_client(db):
    """Alle verwalteten Netze mit der Bezeichnung ihres Clients, fuer
    Rule-Ziel-Vorschlaege ("bekannte Ziele")."""
    return db.execute(
        """
        SELECT cn.cidr, c.label AS client_label
        FROM client_networks cn
        JOIN clients c ON c.id = cn.client_id
        ORDER BY c.label, cn.cidr
        """
    ).fetchall()
