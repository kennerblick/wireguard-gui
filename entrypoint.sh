#!/bin/bash
set -e

mkdir -p /data/db

EXEC_MODE="${EXEC_MODE:-ssh}"

if [ "$EXEC_MODE" = "local" ]; then
  echo "=================================================================="
  echo "EXEC_MODE=local: wg-acl-manager verwaltet iptables direkt auf"
  echo "diesem Host - kein eigener WireGuard-Tunnel, kein SSH-Key noetig."
  echo "Voraussetzung: Container laeuft mit 'network_mode: host' und"
  echo "'cap_add: NET_ADMIN' (siehe docker-compose.local.yml)."
  echo "=================================================================="
  cd /app
  exec waitress-serve --host=0.0.0.0 --port=8080 app:app
fi

### Ab hier: EXEC_MODE=ssh (Standard) - eigener WG-Tunnel + SSH zum Ziel ###

mkdir -p /data/wg /data/ssh
chmod 700 /data/wg /data/ssh

CONTAINER_WG_IP="${CONTAINER_WG_IP:-10.250.0.250}"
ISURFER_WG_IP="${ISURFER_WG_IP:-10.250.0.1}"

### 1) WireGuard-Schluesselpaar erzeugen (nur beim allerersten Start) ###
if [ ! -f /data/wg/privatekey ]; then
  umask 077
  wg genkey | tee /data/wg/privatekey | wg pubkey > /data/wg/publickey
  echo "[entrypoint] Neues WireGuard-Schluesselpaar erzeugt."
fi
CONTAINER_WG_PUBKEY=$(cat /data/wg/publickey)

### 2) SSH-Schluesselpaar erzeugen (nur beim allerersten Start) ###
if [ ! -f /data/ssh/id_ed25519 ]; then
  ssh-keygen -t ed25519 -f /data/ssh/id_ed25519 -N "" -C "wg-acl-manager" >/dev/null
  echo "[entrypoint] Neues SSH-Schluesselpaar erzeugt."
fi
chmod 600 /data/ssh/id_ed25519

### 3) WireGuard-Konfiguration schreiben ###
if [ -z "${ISURFER_PUBKEY:-}" ] || [ -z "${ISURFER_ENDPOINT:-}" ]; then
  echo "=================================================================="
  echo "FEHLER: ISURFER_PUBKEY und/oder ISURFER_ENDPOINT nicht gesetzt."
  echo "Bitte in der .env-Datei eintragen (siehe .env.example) und den"
  echo "Container neu starten."
  echo "=================================================================="
  echo ""
  echo "Dein Container-Public-Key (fuer den Peer-Eintrag auf isurfer.de):"
  echo "  ${CONTAINER_WG_PUBKEY}"
  echo ""
  sleep 3600
  exit 1
fi

cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(cat /data/wg/privatekey)
Address = ${CONTAINER_WG_IP}/32

[Peer]
PublicKey = ${ISURFER_PUBKEY}
Endpoint = ${ISURFER_ENDPOINT}
AllowedIPs = ${ISURFER_WG_IP}/32
PersistentKeepalive = 25
EOF
chmod 600 /etc/wireguard/wg0.conf

### 4) WireGuard-Interface starten ###
wg-quick up wg0 || {
  echo "[entrypoint] wg-quick up fehlgeschlagen - laeuft der Container mit --cap-add=NET_ADMIN und /dev/net/tun?"
  exit 1
}

echo "=================================================================="
echo "WireGuard-Tunnel aktiv. Container-IP: ${CONTAINER_WG_IP}"
echo ""
echo "Container-WG-Public-Key (auf isurfer.de als Peer eintragen, falls noch nicht geschehen):"
echo "  ${CONTAINER_WG_PUBKEY}"
echo ""
echo "Container-SSH-Public-Key (auf isurfer.de in ~/.ssh/authorized_keys eintragen):"
cat /data/ssh/id_ed25519.pub
echo "=================================================================="

### 5) Kurzer Verbindungstest (nicht fatal, nur Hinweis) ###
sleep 2
if ping -c1 -W2 "${ISURFER_WG_IP}" >/dev/null 2>&1; then
  echo "[entrypoint] isurfer.de (${ISURFER_WG_IP}) ist per Ping erreichbar."
else
  echo "[entrypoint] WARNUNG: isurfer.de (${ISURFER_WG_IP}) antwortet nicht auf Ping. Pruefe den Peer-Eintrag auf isurfer.de."
fi

### 6) App starten (Produktions-WSGI-Server statt Flask-Dev-Server) ###
cd /app
exec waitress-serve --host=0.0.0.0 --port=8080 app:app
