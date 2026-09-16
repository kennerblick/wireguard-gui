"""Client-Bereitstellung ("Client bereitstellen"): Setup-Skripte fuer neue
WireGuard-Clients generieren (Linux/Windows/MikroTik) und einen fertigen
Peer auf dem Ziel-Server registrieren.

Der private Schluessel eines neuen Peers wird IMMER lokal auf dessen eigenem
Geraet erzeugt (im generierten Skript selbst) und verlaesst es nie. Diese App
sieht nur den resultierenden Public Key (Schritt 2, register_peer_on_target)
und registriert damit den Peer auf dem Ziel-Server - live per "wg set" und
dauerhaft per Eintrag in der Server-Config.
"""

import base64
import ipaddress

from . import config, wireguard


def suggest_free_ip(db):
    """Schlaegt die naechste freie IP im konfigurierten Subnetz vor.

    Liest das Subnetz aus der [Interface]-Address-Zeile der Ziel-Config und
    schliesst bereits vergebene IPs aus (WireGuard-Peers laut Config,
    Clients laut DB, sowie die Adresse des Interfaces selbst). Gibt
    (ip_oder_None, fehlertext_oder_None) zurueck.
    """
    info = wireguard.fetch_wg_interface_info()
    address = info.get("address")
    if not address:
        return None, "Konnte Subnetz nicht ermitteln (Address in [Interface] fehlt/nicht lesbar)."
    try:
        interface = ipaddress.ip_interface(address)
    except ValueError:
        return None, f"Ungueltige Address-Zeile in der Config: {address!r}"

    used = {str(interface.ip)}
    for peer in wireguard.fetch_wg_peers_from_config():
        ip = wireguard.peer_own_ip(peer)
        if ip:
            used.add(ip)
    for row in db.execute("SELECT wg_ip FROM clients").fetchall():
        used.add(row["wg_ip"])

    for candidate in interface.network.hosts():
        if str(candidate) not in used:
            return str(candidate), None
    return None, "Keine freie IP im Subnetz gefunden."


def validate_wg_pubkey(pubkey: str):
    """Prueft, ob ein String ein plausibler WireGuard-Public-Key ist
    (Base64-kodierter 32-Byte-Wert). Gibt den getrimmten Key oder None zurueck."""
    pubkey = pubkey.strip()
    try:
        raw = base64.b64decode(pubkey, validate=True)
    except Exception:
        return None
    return pubkey if len(raw) == 32 else None


LINUX_SCRIPT_TEMPLATE = """#!/bin/bash
set -e

### Automatisch erzeugt von wg-acl-manager - Client: @@LABEL@@ (@@IP@@) ###

echo "=== Tunnel-IP fuer diesen Server: @@IP@@/24 (Label: @@LABEL@@) ==="

### 1) WireGuard-Tools installieren, falls nicht vorhanden ###
if ! command -v wg >/dev/null 2>&1; then
  echo "Installiere wireguard-tools..."
  if command -v apt >/dev/null 2>&1; then
    apt update && apt install -y wireguard-tools
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y wireguard-tools
  else
    echo "FEHLER: Kein unterstuetzter Paketmanager gefunden - wireguard-tools manuell installieren."
    exit 1
  fi
else
  echo "wireguard-tools bereits installiert."
fi

### 2) Schluesselpaar erzeugen (nur wenn noch nicht vorhanden) ###
mkdir -p /etc/wireguard
chmod 700 /etc/wireguard

if [ -f /etc/wireguard/privatekey ]; then
  echo "Vorhandenes Schluesselpaar gefunden, wird wiederverwendet."
else
  umask 077
  wg genkey | tee /etc/wireguard/privatekey | wg pubkey > /etc/wireguard/publickey
  echo "Neues Schluesselpaar erzeugt."
fi

PRIVATE_KEY=$(cat /etc/wireguard/privatekey)
PUBLIC_KEY=$(cat /etc/wireguard/publickey)

### 3) wg0.conf erzeugen ###
if [ -f /etc/wireguard/wg0.conf ]; then
  echo "WARNUNG: /etc/wireguard/wg0.conf existiert bereits - wird NICHT ueberschrieben."
  echo "Bitte manuell pruefen/anpassen. Abbruch."
  exit 1
fi

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = ${PRIVATE_KEY}
Address = @@IP@@/24
ListenPort = 51820

[Peer]
PublicKey = @@HUB_PUBKEY@@
Endpoint = @@HUB_ENDPOINT@@
AllowedIPs = @@NETWORK_CIDR@@
PersistentKeepalive = 25
EOF

chmod 600 /etc/wireguard/wg0.conf

### 4) Interface aktivieren und beim Boot starten ###
systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
wg-quick up wg0
@@SYSLOG_BLOCK@@
echo ""
echo "================================================================"
echo "Fertig auf diesem Client. Aktueller Status:"
wg show wg0
echo "================================================================"
echo ""
echo ">>> Diesen Public Key in wg-acl-manager unter 'Client bereitstellen' -> Schritt 2 eintragen: <<<"
echo ""
echo "${PUBLIC_KEY}"
echo "================================================================"
"""

LINUX_SYSLOG_BLOCK = """
### 5) rsyslog-Forwarding einrichten ###
if [ ! -d /etc/rsyslog.d ]; then
  echo "WARNUNG: /etc/rsyslog.d nicht gefunden - ist rsyslog installiert? Ueberspringe Log-Forwarding."
else
  cat > /etc/rsyslog.d/60-forward-to-fluentbit.conf <<RSYSLOG_EOF
*.warning    @@@SYSLOG_HOST@@:@@SYSLOG_PORT@@
RSYSLOG_EOF
  systemctl restart rsyslog
  echo "rsyslog-Forwarding eingerichtet: *.warning -> @@SYSLOG_HOST@@:@@SYSLOG_PORT@@"
  logger -p user.warning "Testnachricht von @@LABEL@@ (@@IP@@) ueber WireGuard"
fi
"""

WINDOWS_SCRIPT_TEMPLATE = """# setup-wg-client.ps1
# Automatisch erzeugt von wg-acl-manager - Client: @@LABEL@@ (@@IP@@)
# Nutzung (PowerShell als Administrator): .\\setup-wg-client.ps1

$WgExe = "C:\\Program Files\\WireGuard\\wg.exe"
$WireGuardExe = "C:\\Program Files\\WireGuard\\wireguard.exe"
$ConfigDir = "C:\\WireGuard-Configs"
$TunnelIP = "@@IP@@"
$Label = "@@LABEL@@"
$HubPubKey = "@@HUB_PUBKEY@@"
$HubEndpoint = "@@HUB_ENDPOINT@@"
$NetworkCidr = "@@NETWORK_CIDR@@"
$ConfigFile = "$ConfigDir\\$Label.conf"

if (-not (Test-Path $WgExe)) {
    Write-Error "wg.exe nicht gefunden unter $WgExe - ist WireGuard for Windows installiert?"
    exit 1
}

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null

if (Test-Path $ConfigFile) {
    Write-Warning "Config $ConfigFile existiert bereits - wird nicht ueberschrieben. Abbruch."
    exit 1
}

Write-Host "=== Erzeuge Schluesselpaar ==="
$PrivateKey = & $WgExe genkey
$PublicKey = $PrivateKey | & $WgExe pubkey

$ConfigContent = @"
[Interface]
PrivateKey = $PrivateKey
Address = $TunnelIP/32

[Peer]
PublicKey = $HubPubKey
Endpoint = $HubEndpoint
AllowedIPs = $NetworkCidr
PersistentKeepalive = 25
"@

Set-Content -Path $ConfigFile -Value $ConfigContent -Encoding ASCII

Write-Host "=== Tunnel-Config erstellt: $ConfigFile ==="
Write-Host "=== Installiere als Windows-Dienst (autostart, laeuft auch ohne Login) ==="
& $WireGuardExe /installtunnelservice $ConfigFile

Write-Host ""
Write-Host "================================================================"
Write-Host "Fertig. Tunnel-IP: $TunnelIP (Label: $Label)"
Write-Host "================================================================"
Write-Host ""
Write-Host ">>> Diesen Public Key in wg-acl-manager unter 'Client bereitstellen' -> Schritt 2 eintragen: <<<"
Write-Host ""
Write-Host "$PublicKey"
Write-Host "================================================================"
"""

MIKROTIK_SCRIPT_TEMPLATE = """# MikroTik WireGuard Setup
# Automatisch erzeugt von wg-acl-manager - Client: @@LABEL@@ (@@IP@@)
# Im RouterOS-Terminal (Winbox oder SSH) als Ganzes einfuegen.

/interface/wireguard/add name=wg-client listen-port=51820
/ip/address/add address=@@IP@@/24 interface=wg-client
/interface/wireguard/peers/add interface=wg-client public-key="@@HUB_PUBKEY@@" endpoint-address=@@HUB_ENDPOINT_HOST@@ endpoint-port=@@HUB_ENDPOINT_PORT@@ allowed-address=@@NETWORK_CIDR@@ persistent-keepalive=25s

# Firewall: WireGuard-Handshake von aussen erlauben
/ip/firewall/filter/add chain=input protocol=udp dst-port=51820 action=accept place-before=0 comment="WireGuard @@LABEL@@"

# Firewall: SSH-Management ueber den Tunnel erlauben (fuer zentrale Automatisierung)
/ip/firewall/filter/add chain=input in-interface=wg-client protocol=tcp dst-port=22 action=accept place-before=0 comment="SSH via WireGuard @@LABEL@@"
@@NETWORKS_BLOCK@@
@@SYSLOG_BLOCK@@
:put "=== PUBLIC KEY dieses Routers (in wg-acl-manager unter 'Client bereitstellen' -> Schritt 2 eintragen): ==="
/interface/wireguard/print
"""

MIKROTIK_SYSLOG_BLOCK = """
# Syslog-Forwarding ab warning/error/critical
/system/logging/action/add name=wgaclsyslog target=remote remote=@@SYSLOG_HOST@@ remote-port=@@SYSLOG_PORT@@ src-address=@@IP@@
/system/logging/add topics=warning action=wgaclsyslog
/system/logging/add topics=error action=wgaclsyslog
/system/logging/add topics=critical action=wgaclsyslog
"""

MIKROTIK_NETWORKS_HEADER = """
# Verwaltetes Netz hinter diesem Router - Weiterleitung vom Tunnel erlauben.
# WICHTIG: dieses Netz muss zusaetzlich bereits auf einem anderen Interface
# dieses Routers erreichbar sein (eigenes LAN-Interface/Routing) - dieses
# Skript erzeugt dafuer keine Interface-/Routing-Konfiguration, nur die
# Firewall-Freigabe fuer den Tunnel-Verkehr."""

MIKROTIK_NETWORK_BLOCK = """
/ip/firewall/filter/add chain=forward in-interface=wg-client dst-address=@@NET@@ action=accept place-before=0 comment="LAN @@NET@@ via WireGuard @@LABEL@@"
/ip/firewall/filter/add chain=forward out-interface=wg-client src-address=@@NET@@ action=accept place-before=0 comment="LAN @@NET@@ via WireGuard @@LABEL@@ (Antwortverkehr)"
"""


def _fill_template(template: str, **values) -> str:
    for key, val in values.items():
        template = template.replace(f"@@{key}@@", val)
    return template


def render_linux_script(label, ip, hub_pubkey, hub_endpoint, network_cidr, syslog_host):
    syslog_block = ""
    if syslog_host:
        syslog_block = _fill_template(
            LINUX_SYSLOG_BLOCK,
            SYSLOG_HOST=syslog_host,
            SYSLOG_PORT=config.SYSLOG_PORT_LINUX,
            LABEL=label,
            IP=ip,
        )
    return _fill_template(
        LINUX_SCRIPT_TEMPLATE,
        LABEL=label,
        IP=ip,
        HUB_PUBKEY=hub_pubkey,
        HUB_ENDPOINT=hub_endpoint,
        NETWORK_CIDR=network_cidr,
        SYSLOG_BLOCK=syslog_block,
    )


def render_windows_script(label, ip, hub_pubkey, hub_endpoint, network_cidr):
    return _fill_template(
        WINDOWS_SCRIPT_TEMPLATE,
        LABEL=label,
        IP=ip,
        HUB_PUBKEY=hub_pubkey,
        HUB_ENDPOINT=hub_endpoint,
        NETWORK_CIDR=network_cidr,
    )


def render_mikrotik_script(label, ip, hub_pubkey, hub_endpoint, network_cidr, syslog_host, managed_networks=None):
    endpoint_host, _, endpoint_port = hub_endpoint.rpartition(":")
    syslog_block = ""
    if syslog_host:
        syslog_block = _fill_template(
            MIKROTIK_SYSLOG_BLOCK,
            SYSLOG_HOST=syslog_host,
            SYSLOG_PORT=config.SYSLOG_PORT_MIKROTIK,
            IP=ip,
        )
    networks_block = ""
    if managed_networks:
        networks_block = MIKROTIK_NETWORKS_HEADER + "".join(
            _fill_template(MIKROTIK_NETWORK_BLOCK, NET=net, LABEL=label) for net in managed_networks
        )
    return _fill_template(
        MIKROTIK_SCRIPT_TEMPLATE,
        LABEL=label,
        IP=ip,
        HUB_PUBKEY=hub_pubkey,
        HUB_ENDPOINT_HOST=endpoint_host or hub_endpoint,
        HUB_ENDPOINT_PORT=endpoint_port or "51820",
        NETWORK_CIDR=network_cidr,
        SYSLOG_BLOCK=syslog_block,
        NETWORKS_BLOCK=networks_block,
    )


def register_peer_on_target(pubkey: str, ip: str, label: str, extra_networks=None):
    """Registriert einen neuen Peer live UND persistent auf dem Ziel-Server.

    Fuegt den Peer per "wg set" sofort hinzu (wirkt ohne Neustart) und haengt
    - falls noch nicht vorhanden - einen [Peer]-Block mit #Name-Kommentar an
    die Config-Datei an, damit er auch einen Neustart/wg-quick-Neuaufbau
    uebersteht. pubkey/ip/label muessen vom Aufrufer bereits validiert sein
    (validate_wg_pubkey/ipaddress/config.LABEL_RE) - sie fliessen direkt in
    ein per SSH oder lokal ausgefuehrtes Bash-Script ein.

    extra_networks: optionale Liste bereits validierter CIDRs (siehe
    networks.validate_network_cidr) fuer Netze, die dieser Peer verwaltet
    (typisch ein MikroTik-Router mit einem LAN dahinter). Werden zusaetzlich
    zur eigenen /32-Adresse in die AllowedIPs des Peers auf dem Server
    aufgenommen - ohne das wuerde der Server Pakete an dieses Netz gar nicht
    erst zu diesem Peer routen, egal welche ACL-Regeln in dieser App dafuer
    bestehen.
    """
    iface = config.TARGET_WG_INTERFACE
    allowed_ips = ",".join([f"{ip}/32", *(extra_networks or [])])
    script = (
        "set -e\n"
        f"wg set {iface} peer {pubkey} allowed-ips {allowed_ips}\n"
        f'CONF=/etc/wireguard/{iface}.conf\n'
        f'if ! grep -qF "{pubkey}" "$CONF" 2>/dev/null; then\n'
        f'  printf "\\n[Peer]\\n#{label}\\nPublicKey = {pubkey}\\nAllowedIPs = {allowed_ips}\\n" >> "$CONF"\n'
        f'  echo "Peer dauerhaft in $CONF eingetragen."\n'
        f"else\n"
        f'  echo "Peer war bereits in $CONF eingetragen - nicht dupliziert."\n'
        f"fi\n"
    )
    return wireguard.run_on_target(script)
