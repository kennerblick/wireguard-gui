# WireGuard ACL Manager

Lokaler Docker-Container mit Web-GUI zur Verwaltung, welcher WireGuard-Peer
im `isurfer.de`-Mesh (`10.250.0.0/24`) auf welche Ziele und Dienste
zugreifen darf. Setzt auf die iptables-`DOCKER-USER`-Chain auf isurfer.de
auf (siehe `wireguard`-Repo, Troubleshooting-Abschnitt zu Docker/FORWARD).

## Funktionsweise

- Der Container baut selbst einen WireGuard-Tunnel zu isurfer.de auf (nur
  zu dessen Tunnel-IP, nicht zum ganzen `/24` - Least Privilege).
- Über diesen Tunnel verbindet sich der Container per SSH zu isurfer.de
  und verwaltet dort gezielt iptables-Regeln.
- Für jeden in der App als "eingeschränkt" markierten Client wird eine
  eigene Chain (`WGACL_<ip-mit-unterstrichen>`) angelegt: erst die
  erlaubten `ACCEPT`-Regeln (Ziel + Dienst), dann ein abschließendes
  `DROP`. Ein Sprung dorthin wird oben in `DOCKER-USER` eingefügt - **vor**
  der bestehenden pauschalen `wg0→wg0`-Regel.
- Clients, die nicht in der App auftauchen (oder als "uneingeschränkt"
  markiert sind), bleiben von der pauschalen Regel abgedeckt - volles Mesh,
  wie bisher.

## Voraussetzungen

- Docker + Docker Compose lokal installiert.
- Der Client, den du einschränken willst, muss bereits als regulärer
  WireGuard-Peer auf isurfer.de eingetragen sein (siehe `wireguard`-Repo).
- `iptables-persistent` auf isurfer.de installiert (für dauerhafte Regeln
  über Neustarts hinweg) - siehe `wireguard`-Repo, Troubleshooting.

## Einrichtung

### 1. Konfiguration

```bash
cp .env.example .env
```

`.env` ausfüllen: `ISURFER_PUBKEY` und `ISURFER_ENDPOINT` stehen schon
korrekt drin (aus eurer bestehenden Doku), `CONTAINER_WG_IP` auf ein
freies Oktett setzen (z.B. `10.250.0.250`), `FLASK_SECRET` mit
`openssl rand -hex 32` erzeugen.

### 2. Container bauen und starten

```bash
docker compose up -d --build
```

### 3. Logs prüfen - Container-Keys ablesen

```bash
docker compose logs -f
```

Der Container gibt beim ersten Start zwei Schlüssel aus:

```
Container-WG-Public-Key (auf isurfer.de als Peer eintragen, falls noch nicht geschehen):
  <WG_PUBKEY>

Container-SSH-Public-Key (auf isurfer.de in ~/.ssh/authorized_keys eintragen):
  ssh-ed25519 AAAA... wg-acl-manager
```

### 4. Container als WireGuard-Peer auf isurfer.de eintragen

```bash
wg set wg0 peer <WG_PUBKEY> allowed-ips 10.250.0.250/32
```

Und dauerhaft in `/etc/wireguard/wg0.conf`:
```
[Peer]
#wg-acl-manager (lokales Management-Tool)
PublicKey = <WG_PUBKEY>
AllowedIPs = 10.250.0.250/32
```

### 5. SSH-Key auf isurfer.de hinterlegen

```bash
echo "ssh-ed25519 AAAA... wg-acl-manager" >> ~/.ssh/authorized_keys
```
(auf isurfer.de, im Home-Verzeichnis des in `.env` gewählten `ISURFER_SSH_USER`)

### 6. Container neu starten und testen

```bash
docker compose restart
```

Web-UI öffnen: http://localhost:8080

Das Dashboard sollte oben den "WireGuard-Status" von isurfer.de anzeigen
(alle aktuellen Peers mit Handshake-Zeiten) - das bestätigt, dass Tunnel
und SSH-Zugriff funktionieren.

## Nutzung

1. **Client hinzufügen**: Tunnel-IP + Bezeichnung eintragen. Neu
   hinzugefügte Clients sind standardmäßig "eingeschränkt" - ohne Regeln
   bedeutet das: **kein** Zugriff auf irgendetwas im Mesh (nur `DROP`).
2. **Regeln hinzufügen**: Pro Client Ziel-IP (oder `any`) + Dienst wählen.
   Wird sofort angewendet.
3. **Einschränkung umschalten**: Ein Client kann jederzeit auf
   "uneingeschränkt" gesetzt werden - dann greift wieder die normale
   Mesh-Regel, die eigene Chain wird zurückgebaut.
4. **Dienste verwalten**: Unter "Dienste" eigene Ports/Protokolle
   ergänzen, zusätzlich zu den mitgelieferten Standarddiensten (SSH, RDP,
   HTTPS-Alt 8443, PostgreSQL, Proxmox VE, HTTP, HTTPS, "Alle Ports").

## Allgemeine Nutzung (nicht nur isurfer.de)

Das Tool geht davon aus, dass der Ziel-WireGuard-Server ein Linux-Host mit
`iptables` ist, bei dem Peer-zu-Peer-Traffic durch den Server selbst
geroutet wird (Hub-and-Spoke, `net.ipv4.ip_forward=1`). Zwei Dinge werden
beim Start/bei jedem "Anwenden" automatisch erkannt und im Dashboard
angezeigt:

- **Einhängepunkt der Regeln:** Existiert eine `DOCKER-USER`-Chain (typisch
  bei Servern mit Docker, wie isurfer.de), werden die Client-Chains dort
  eingehängt. Sonst direkt oben in `FORWARD`.
- **IP-Forwarding-Status:** Wird als Warnung angezeigt, falls inaktiv - dann
  liefe die ganze ACL-Logik ins Leere, weil gar kein Peer-zu-Peer-Traffic
  durch den Server geht.

**`TARGET_WG_INTERFACE`** (Standard `wg0`) muss auf den tatsächlichen
Interface-Namen des Ziel-WG-Servers gesetzt werden - das ist NICHT
zwangsläufig `wg0`. Beispiel aus unserer eigenen Umgebung: Einer unserer
MikroTik-Router nutzt `WG-Logging` statt des sonst überall verwendeten
`wg-isurfer`.

**Persistenz:** Das Tool versucht `netfilter-persistent save` - ist das auf
dem Zielserver nicht installiert, werden die Regeln trotzdem angewendet,
aber mit einer Warnung im Log, dass sie einen Neustart nicht überleben.

## Sicherheitshinweise

- Der SSH-Zugriff erfolgt aktuell mit dem `root`-User auf isurfer.de
  (Standard in `.env`). Für mehr Härtung: eigenen User auf isurfer.de
  anlegen, der per `sudoers` nur `iptables`, `netfilter-persistent` und
  `wg show` ohne Passwort ausführen darf, und `ISURFER_SSH_USER`
  entsprechend anpassen.
- `FLASK_SECRET` unbedingt individuell setzen (nicht den Default aus
  `.env.example` übernehmen).
- Die Web-UI selbst hat aktuell **keine Authentifizierung** - nur für den
  lokalen Rechner/vertrauenswürdiges Netz gedacht. Bei Bedarf einen
  Reverse-Proxy mit Basic-Auth oder OAuth davorsetzen.

## Troubleshooting

**Dashboard zeigt "Konnte Status nicht abrufen":**
- Prüfen, ob der WG-Tunnel steht: `docker compose exec wg-acl-manager wg show wg0`
- Prüfen, ob der SSH-Key auf isurfer.de hinterlegt ist (Schritt 5)
- Prüfen, ob `ISURFER_WG_IP` in `.env` mit der tatsächlichen Tunnel-IP von
  isurfer.de übereinstimmt (Standard: `10.250.0.1`)

**Regeln werden gespeichert, aber "Anwenden fehlgeschlagen":**
- Fehlermeldung aus der Flash-Message zeigt meist direkt die SSH-/iptables-
  Fehlerausgabe. Häufigste Ursache: SSH-Key noch nicht in
  `authorized_keys`, oder `ISURFER_SSH_USER` hat keine Root-/sudo-Rechte
  für `iptables`.
