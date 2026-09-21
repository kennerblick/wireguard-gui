"""iptables-Seite: Chain-Namen, Script-Generierung, Ist-Zustand auslesen/
interpretieren. Kein direkter DB-Zugriff - reine Firewall-/Netz-Logik.
"""

import ipaddress
import re

from . import config, wireguard

IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\b")


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


def detect_hook_chain() -> str:
    """Ermittelt, wohin die Client-Chains eingehaengt werden sollen.

    Server mit Docker (z.B. weil dort auch andere Container laufen) haben
    eine DOCKER-USER-Chain, die vor Docker's eigener FORWARD-Logik
    ausgewertet wird - dort ist der richtige Ort fuer eigene Regeln, weil
    Docker die FORWARD-Policy sonst ueberschreibt. Server ohne Docker haben
    diese Chain nicht; dort wird direkt oben in FORWARD eingehaengt.
    """
    ok, _ = wireguard.run_on_target("iptables -L DOCKER-USER -n >/dev/null 2>&1")
    return "DOCKER-USER" if ok else "FORWARD"


def check_ip_forward():
    ok, out = wireguard.run_on_target("cat /proc/sys/net/ipv4/ip_forward")
    if not ok:
        return None
    return out.strip() == "1"


def _ensure_established_related_rule_line(hook_chain: str, iface: str) -> str:
    """Stellt sicher, dass Rueckantworten auf bereits erlaubte Verbindungen
    unabhaengig von der (potenziell restriktiven) Chain des ANTWORTENDEN
    Peers durchgelassen werden.

    Ohne diese Regel filtert jede Peer-Chain ausschliesslich nach Quelle: eine
    Regel "A darf zu B" erlaubt zwar das erste Paket A->B, nicht aber automatisch
    die Antwort B->A (z.B. eine Ping-Antwort oder ein TCP-SYN-ACK) - die laeuft
    durch B's EIGENE Chain, gefiltert nach B's eigenen (moeglicherweise leeren)
    Regeln, und wuerde dort im finalen DROP landen. Ohne diese Regel muesste
    man fuer jedes kommunizierende Peer-Paar zwingend BEIDE Richtungen einzeln
    konfigurieren, nur damit Antworten ueberhaupt zurueckkommen (in Produktion
    aufgetreten: ein Client mit "erlaube Zugriff auf X" konnte X zwar erreichen,
    bekam aber nie eine Antwort, weil X selbst keine Regel zurueck hatte).

    Eine einmalige, auf wg-zu-wg-Forwarding beschraenkte (-i/-o {iface}, ruehrt
    keinen anderen Forwarding-Traffic auf dem Host an) ESTABLISHED,RELATED-
    Accept-Regel ganz oben in der Hook-Chain (Position 1) loest das: eine
    bereits ueber eine explizite Regel erlaubte Verbindung darf antworten, ohne
    dass der antwortende Peer selbst eine (redundante) Spiegel-Regel braucht.
    Eine NEUE, vom antwortenden Peer selbst ausgehende Verbindung braucht
    weiterhin eine eigene, explizite Regel - das hier lockert nur Rueckantworten
    auf bereits vom initiierenden Client erlaubte Verbindungen, nicht mehr.
    Muss vor der eigenen Sprung-Regel des Clients installiert werden (siehe
    Aufrufer), die deshalb explizit auf Position 2 eingefuegt wird - sonst
    wuerde ein spaeterer bare `-I {hook_chain}`-Aufruf fuer einen anderen
    Client diese Regel wieder von Position 1 verdraengen.
    """
    return (
        f'iptables -C {hook_chain} -i {iface} -o {iface} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null '
        f'|| iptables -I {hook_chain} 1 -i {iface} -o {iface} -m state --state ESTABLISHED,RELATED -j ACCEPT'
    )


def build_apply_script(client_ip: str, rules: list, hook_chain: str) -> str:
    """Baut das idempotente iptables-Script fuer einen einzelnen Client.

    rules: Liste bereits aufgeloester Ziele ({"dest_ip", "protocol", "port"}) -
    Gruppen-Regeln (dest_tag_id) muessen vom Aufrufer vorher per
    acl.resolve_rule_targets() zu konkreten IPs expandiert worden sein.
    """
    chain = chain_name(client_ip)
    iface = config.TARGET_WG_INTERFACE
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
            # Portbereiche werden als "start-end" gespeichert (wie die IP-Bereiche
            # in config.py), iptables --dport erwartet dafuer aber "start:end".
            dport = str(port).replace("-", ":")
            proto_part = f"-p {proto} --dport {dport} "
        lines.append(f'iptables -A {chain} {dest_part}{proto_part}-j ACCEPT'.replace("  ", " "))

    lines.append(f'iptables -A {chain} -j DROP')
    lines.append(_ensure_established_related_rule_line(hook_chain, iface))
    lines.append(
        f'iptables -C {hook_chain} -i {iface} -o {iface} -s {client_ip} -j {chain} 2>/dev/null '
        f'|| iptables -I {hook_chain} 2 -i {iface} -o {iface} -s {client_ip} -j {chain}'
    )
    lines.append(
        'command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save '
        '|| echo "HINWEIS: netfilter-persistent nicht gefunden - Regeln ueberleben KEINEN Neustart. '
        'Manuell persistieren, z.B. mit iptables-save."'
    )
    return "\n".join(lines) + "\n"


def build_remove_script(client_ip: str, hook_chain: str) -> str:
    chain = chain_name(client_ip)
    iface = config.TARGET_WG_INTERFACE
    return (
        "set -e\n"
        f'iptables -D {hook_chain} -i {iface} -o {iface} -s {client_ip} -j {chain} 2>/dev/null || true\n'
        f'iptables -F {chain} 2>/dev/null || true\n'
        f'iptables -X {chain} 2>/dev/null || true\n'
        'command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save || true\n'
    )


def list_remote_wgacl_chains():
    """Listet alle WGACL_*-Chains auf dem Zielserver auf (ok, chains_oder_fehlertext)."""
    ok, out = wireguard.run_on_target(
        "iptables-save 2>/dev/null | grep -oE '^:WGACL_[A-Za-z0-9_]+' | sed 's/^://' | sort -u"
    )
    if not ok:
        return False, out
    return True, [c for c in out.split() if c]


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
