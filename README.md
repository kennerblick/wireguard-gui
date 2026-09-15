# WireGuard ACL Manager

Docker-Container mit Web-GUI zur Verwaltung, welcher WireGuard-Peer in
einem Hub-and-Spoke-Mesh auf welche Ziele und Dienste zugreifen darf. Setzt
auf die iptables-`DOCKER-USER`-Chain auf dem Zielserver auf (falls
vorhanden, sonst auf `FORWARD` - siehe "Allgemeine Nutzung" unten).

Es gibt zwei Betriebsarten (`EXEC_MODE` in `.env`):

- **`ssh`** (Standard) - der Container läuft auf einer **separaten**
  Maschine (z.B. deinem Admin-Rechner), baut selbst einen WireGuard-Tunnel
  zum Ziel-Server auf und verwaltet dort per SSH die iptables-Regeln. Siehe
  Abschnitt "Einrichtung (EXEC_MODE=ssh)".
- **`local`** - der Container läuft **direkt auf dem WireGuard-Server
  selbst** und verwaltet iptables ohne Tunnel/SSH direkt auf dem Host.
  Siehe Abschnitt "Betrieb direkt auf dem WG-Server (EXEC_MODE=local)".

## Funktionsweise (EXEC_MODE=ssh)

- Der Container baut selbst einen WireGuard-Tunnel zum Zielserver auf (nur
  zu dessen Tunnel-IP, nicht zum ganzen `/24` - Least Privilege).
- Über diesen Tunnel verbindet sich der Container per SSH zum Zielserver
  und verwaltet dort gezielt iptables-Regeln.
- Für jeden in der App als "eingeschränkt" markierten Client wird eine
  eigene Chain (`WGACL_<ip-mit-unterstrichen>`) angelegt: erst die
  erlaubten `ACCEPT`-Regeln (Ziel + Dienst), dann ein abschließendes
  `DROP`. Ein Sprung dorthin wird oben in `DOCKER-USER` eingefügt - **vor**
  einer eventuell bestehenden pauschalen Mesh-Regel.
- Clients, die nicht in der App auftauchen (oder als "uneingeschränkt"
  markiert sind), bleiben von der Grundkonfiguration des Zielservers
  abgedeckt - was das konkret bedeutet, hängt von eurem Setup ab (siehe
  Punkt 3 unter "Nutzung").

Im `local`-Modus entfällt der Tunnel/SSH-Schritt komplett: derselbe
Chain-Mechanismus (`WGACL_*`, `DROP`, Hook in `DOCKER-USER`/`FORWARD`)
wird stattdessen direkt auf dem Host ausgeführt, auf dem der Container
läuft.

## Voraussetzungen

- Docker + Docker Compose installiert (auf dem Admin-Rechner bei
  `EXEC_MODE=ssh`, bzw. auf dem WG-Server selbst bei `EXEC_MODE=local`).
- Der Client, den du einschränken willst, muss bereits als regulärer
  WireGuard-Peer auf dem Zielserver eingetragen sein (oder per "Client
  bereitstellen" neu angelegt werden, siehe "Nutzung").
- `iptables-persistent` auf dem Zielserver installiert (für dauerhafte
  Regeln über Neustarts hinweg, relevant für **nicht** von dieser App
  verwaltete Grundregeln). Für die von dieser App selbst erzeugten
  `WGACL_*`-Regeln reicht das nicht zwingend aus (siehe "Persistenz" unten).

## Einrichtung (EXEC_MODE=ssh)

### 1. Konfiguration

```bash
cp .env.example .env
```

`.env` ausfüllen: `WG_SERVER_PUBKEY` und `WG_SERVER_ENDPOINT` aus eurer
bestehenden Doku eintragen, `CONTAINER_WG_IP` auf ein freies Oktett setzen
(z.B. `10.250.0.250`), `FLASK_SECRET` mit `openssl rand -hex 32` erzeugen.
Sobald die Web-UI aus einem gemeinsam genutzten Netz erreichbar sein soll,
zusätzlich `ADMIN_USER`/`ADMIN_PASSWORD` setzen (siehe Sicherheitshinweise).

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
Container-WG-Public-Key (auf dem Zielserver als Peer eintragen, falls noch nicht geschehen):
  <WG_PUBKEY>

Container-SSH-Public-Key (auf dem Zielserver in ~/.ssh/authorized_keys eintragen):
  ssh-ed25519 AAAA... wg-acl-manager
```

### 4. Container als WireGuard-Peer auf dem Zielserver eintragen

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

### 5. SSH-Key auf dem Zielserver hinterlegen

```bash
echo "ssh-ed25519 AAAA... wg-acl-manager" >> ~/.ssh/authorized_keys
```
(auf dem Zielserver, im Home-Verzeichnis des in `.env` gewählten `WG_SERVER_SSH_USER`)

### 6. Container neu starten und testen

```bash
docker compose restart
```

Web-UI öffnen: http://localhost:8080

Das Dashboard sollte oben den "WireGuard-Status" des Zielservers anzeigen
(alle aktuellen Peers mit Handshake-Zeiten) - das bestätigt, dass Tunnel
und SSH-Zugriff funktionieren.

## Betrieb direkt auf dem WG-Server (EXEC_MODE=local)

Für den Fall, dass wg-acl-manager nicht separat, sondern direkt auf dem
WireGuard-Hub selbst laufen soll - kein eigener Tunnel, kein SSH-Key, die
App manipuliert iptables direkt auf dem Host.

**Wichtig - Trade-off:** Der Container läuft dafür mit `network_mode: host`
und `cap_add: NET_ADMIN`, sieht also das komplette Host-Netzwerk (nicht nur
eine einzelne Tunnel-IP wie im `ssh`-Modus) und kann theoretisch beliebige
iptables-Regeln auf dem Host setzen. Das ist für einen alleinstehenden
WG-Server ein akzeptabler, deutlich einfacherer Trade-off - `ADMIN_USER`/
`ADMIN_PASSWORD` daher **unbedingt** setzen, siehe Sicherheitshinweise.

**Wichtig - Dateisystem:** `network_mode: host` teilt nur die Netzwerk-
Namespaces, **nicht** das Dateisystem. `iptables`/`wg show` funktionieren
trotzdem (die wirken direkt auf den geteilten Netzwerk-Namespace), aber um
die Peer-Namen aus `/etc/wireguard/<interface>.conf` zu lesen (siehe
"Nutzung" unten), mountet `docker-compose.local.yml` `/etc/wireguard`
read-only in den Container. Ohne diesen Mount zeigt die Namensspalte nur
"-" an.

### 1. Repo auf dem WG-Server klonen und konfigurieren

```bash
git clone https://github.com/kennerblick/wireguard-gui.git
cd wireguard-gui
cp .env.example .env
```

In `.env`:
```
EXEC_MODE=local
TARGET_WG_INTERFACE=wg0      # tatsaechlicher Interface-Name auf diesem Host
WG_SERVER_ENDPOINT=<oeffentliche IP oder Hostname>:<Port>   # fuer "Client bereitstellen"
FLASK_SECRET=<openssl rand -hex 32>
ADMIN_USER=<admin>
ADMIN_PASSWORD=<starkes-passwort>
```
Die übrigen `WG_SERVER_*`-Variablen (Pubkey, Tunnel-IP, SSH-User) werden in
diesem Modus nicht benötigt/ignoriert.

### 2. Container bauen und starten

```bash
docker compose -f docker-compose.local.yml up -d --build
```

Kein Peer-Eintrag, kein SSH-Key-Deployment nötig - das entfällt komplett in
diesem Modus.

### 3. Testen

Web-UI öffnen: `http://<server-ip>:8080` (Basic-Auth-Login mit den oben
gesetzten Zugangsdaten). Das Dashboard sollte den echten `wg show`-Status
sowie den erkannten Hook-Punkt (`DOCKER-USER`/`FORWARD`) anzeigen - beides
wird jetzt direkt auf diesem Host abgefragt, ohne Tunnel/SSH.

**Hinweis Port-Konflikt:** Wegen `network_mode: host` bindet die App direkt
an Port 8080 auf allen Host-Interfaces - sicherstellen, dass der Port noch
frei ist (`ss -tlnp | grep 8080`).

**Hinweis Persistenz:** Im `local`-Modus baut die App beim Container-(Neu-)
Start automatisch alle in der DB gespeicherten Client-Regeln neu auf (siehe
"Persistenz" unten) - ein separates `iptables-persistent`/
`netfilter-persistent` ist für die `WGACL_*`-Regeln dieser App also nicht
zwingend nötig, wohl aber für eure sonstige, nicht von dieser App verwaltete
iptables-Grundkonfiguration.

## Nutzung

1. **Client hinzufügen**: Tunnel-IP + Bezeichnung eintragen. Neu
   hinzugefügte Clients sind standardmäßig "eingeschränkt" - ohne Regeln
   bedeutet das: **kein** Zugriff auf irgendetwas im Mesh (nur `DROP`). Der
   WireGuard-Peer muss dafür bereits existieren - für einen komplett neuen
   Peer siehe "Client bereitstellen" (Punkt 9).
2. **Regeln hinzufügen**: Pro Client Ziel-IP (oder `any`) + Dienst wählen.
   Wird sofort angewendet.
3. **Einschränkung umschalten**: Ein Client kann jederzeit auf
   "uneingeschränkt" gesetzt werden - dann baut diese App ihre eigene Chain
   für ihn zurück, und es greift wieder das, was ohne wg-acl-manager auf dem
   Zielserver konfiguriert ist (je nach Setup z.B. eine pauschale Mesh-Regel,
   oder auch nur "darf zum Hub"). **Was das im Einzelfall genau bedeutet,
   hängt von eurer tatsächlichen Firewall-Grundkonfiguration ab** - siehe
   "Wartung" → "Firewall-Regeln (Ist-Zustand)", nicht pauschal annehmen.
4. **Dienste verwalten**: Unter "Dienste" eigene Ports/Protokolle
   ergänzen, zusätzlich zu den mitgelieferten Standarddiensten (SSH, RDP,
   HTTPS-Alt 8443, PostgreSQL, Proxmox VE, HTTP, HTTPS, "Alle Ports").
5. **Wartung**: Unter "Wartung" lassen sich verwaiste `WGACL_*`-Chains auf
   dem Zielserver finden und entfernen - z.B. wenn ein Client-Datensatz
   direkt in der Datenbank gelöscht wurde statt über "Entfernen" in der UI.
6. **Netzplan**: Unter "Netzplan" zeigt ein Graph, welcher Peer wohin darf -
   Linie zwischen zwei Peers = mindestens eine Regel erlaubt Zugriff, Maus
   auf die Linie halten zeigt den/die erlaubten Dienst(e). Darunter lässt
   sich voller Zugriff ("Alle Ports") von einem Peer auf beliebige andere
   Peers per Dropdown (Quelle) + Mehrfachauswahl (Ziele, mit Checkbox)
   umschalten - bereits erlaubte Ziele sind vorausgewählt. Einzelne,
   dienstspezifische Regeln bleiben davon unberührt und werden weiterhin
   über das Dashboard verwaltet. Der Graph zeigt nur, was **in dieser App**
   als Regel hinterlegt ist - nicht zwangsläufig, was auf dem Zielserver
   tatsächlich (z.B. durch manuell gesetzte Regeln) erlaubt ist.
7. **Peers importieren**: Button auf dem Dashboard liest die WireGuard-Config
   des Zielservers aus und legt für alle dort vorhandenen, aber in dieser App
   noch unbekannten Peers einen Client-Datensatz an (eingeschränkt, ohne
   Regeln - ändert nichts an der Firewall). Nützlich, um ein bestehendes
   WG-Netz erstzuerfassen, ohne jeden Peer einzeln eintippen zu müssen.
   Wichtig: das behauptet **nichts** über die tatsächlichen Zugriffsrechte
   des Peers - die anhand der echten Firewall-Regeln (siehe Punkt 8) manuell
   nachtragen, bevor für diesen Client "Anwenden" geklickt wird (sonst würde
   er ggf. von allem abgeschnitten, auch vom Hub).
8. **Firewall-Regeln (Ist-Zustand)**: Unter "Wartung" zeigt ein zweiter
   Abschnitt die tatsächlichen `DOCKER-USER`-/`FORWARD`-Regeln vom
   Zielserver, mit Peer-Namen annotiert - read-only, ändert nichts. Eine
   Tabelle interpretiert einfache Regeln automatisch (auch praktisch für
   von Hand gesetzte Policy-Regeln außerhalb dieser App); alles
   Komplexere (Module, Negation, ...) bleibt als Rohtext zum manuellen
   Nachlesen. Damit lässt sich der reale Ist-Zustand nachvollziehen, bevor
   man ihn in dieser App nachbildet.
9. **Client bereitstellen**: Zwei-Schritte-Assistent für einen komplett
   neuen WireGuard-Peer (Windows/Linux/MikroTik). Schritt 1 generiert ein
   Setup-Skript bzw. eine Config mit einer automatisch vorgeschlagenen
   freien Tunnel-IP zum Herunterladen und Ausführen auf dem neuen Gerät -
   der private Schlüssel wird dabei **nur lokal auf diesem Gerät erzeugt
   und verlässt es nie**. Schritt 2 nimmt den vom Skript ausgegebenen
   Public Key entgegen und registriert den Peer live (`wg set`, ohne
   Neustart) sowie dauerhaft (Eintrag in der Server-Config) - und legt
   einen passenden, eingeschränkten Client-Datensatz ohne Regeln an.

**Peer-Namen im Dashboard/Netzplan:** Die Spalte "Name" im WireGuard-Status
sowie die Beschriftungen im Netzplan werden aus der WireGuard-Config des
Ziels gelesen - die **erste Zeile direkt unter `[Peer]`** muss dafür ein
Kommentar mit dem Anzeigenamen sein, z.B.:
```
[Peer]
#Buero-Router
PublicKey = ...
AllowedIPs = 10.250.0.5/32
```
Ohne diesen Kommentar wird ersatzweise die IP (oder, falls der Peer als
Client in der App angelegt ist, dessen "Bezeichnung") angezeigt. "Client
bereitstellen" (Punkt 9) trägt diesen Kommentar automatisch ein.

**Peers mit weiterreichendem Zugriff (AllowedIPs = ganzes Subnetz):** Normalerweise
steht in `AllowedIPs` die eigene `/32`-Adresse des Peers, aus der die App
seine Tunnel-IP ableitet. Bei einem Peer, der auf das gesamte Mesh
zugreifen darf (z.B. ein Admin-Rechner), deckt `AllowedIPs` stattdessen
das ganze Subnetz ab (z.B. `10.250.0.0/24`) - daraus lässt sich die
eigene IP nicht mehr ableiten. Für diesen Fall zusätzlich eine zweite
Kommentarzeile `#IP: x.x.x.x` mit der tatsächlichen eigenen Tunnel-IP
angeben:
```
[Peer]
#PC-Admin
#IP: 10.250.0.201
PublicKey = ...
AllowedIPs = 10.250.0.0/24
```
Ohne diese Zeile würde die App fälschlich die Netzwerk-Adresse (`10.250.0.0`)
als IP dieses Peers annehmen - sowohl beim Anzeigen als auch beim
Importieren ("Peers importieren") und bei der freien-IP-Vorschlagsfunktion
("Client bereitstellen").

## Allgemeine Nutzung

Das Tool geht davon aus, dass der Ziel-WireGuard-Server ein Linux-Host mit
`iptables` ist, bei dem Peer-zu-Peer-Traffic durch den Server selbst
geroutet wird (Hub-and-Spoke, `net.ipv4.ip_forward=1`). Zwei Dinge werden
beim Start/bei jedem "Anwenden" automatisch erkannt und im Dashboard
angezeigt:

- **Einhängepunkt der Regeln:** Existiert eine `DOCKER-USER`-Chain (typisch
  bei Servern mit Docker), werden die Client-Chains dort eingehängt. Sonst
  direkt oben in `FORWARD`.
- **IP-Forwarding-Status:** Wird als Warnung angezeigt, falls inaktiv - dann
  liefe die ganze ACL-Logik ins Leere, weil gar kein Peer-zu-Peer-Traffic
  durch den Server geht.

**`TARGET_WG_INTERFACE`** (Standard `wg0`) muss auf den tatsächlichen
Interface-Namen des Ziel-WG-Servers gesetzt werden - das ist NICHT
zwangsläufig `wg0`, z.B. wenn ein Router einen abweichenden Namen für sein
WireGuard-Interface verwendet.

**Persistenz:** Das Tool versucht `netfilter-persistent save` - ist das auf
dem Zielserver nicht installiert, werden die Regeln trotzdem angewendet,
aber mit einer Warnung im Log, dass sie einen Neustart nicht überleben. Im
`EXEC_MODE=local` baut die App ihre eigenen `WGACL_*`-Regeln bei jedem
Container-(Neu-)Start ohnehin automatisch aus der DB neu auf (siehe oben) -
`netfilter-persistent` ist dort für diese Regeln optional, für sonstige
(nicht von dieser App verwaltete) iptables-Regeln auf dem Host aber weiter
empfehlenswert.

## Sicherheitshinweise

- **EXEC_MODE=ssh:** Der SSH-Zugriff erfolgt aktuell mit dem `root`-User auf
  dem Zielserver (Standard in `.env`). Für mehr Härtung: eigenen User auf
  dem Zielserver anlegen, der per `sudoers` nur `iptables`,
  `netfilter-persistent` und `wg show` ohne Passwort ausführen darf, und
  `WG_SERVER_SSH_USER` entsprechend anpassen.
- **EXEC_MODE=local:** Der Container läuft mit `network_mode: host` +
  `cap_add: NET_ADMIN` und hat damit vollen Zugriff auf die Host-Netzwerk-
  konfiguration (nicht nur auf seine eigenen `WGACL_*`-Chains). `ADMIN_USER`/
  `ADMIN_PASSWORD` sind hier praktisch Pflicht, nicht nur "empfohlen".
- `FLASK_SECRET` unbedingt individuell setzen (nicht den Default aus
  `.env.example` übernehmen).
- Die Web-UI hat standardmäßig **keine Authentifizierung** - nur für den
  lokalen Rechner/vertrauenswürdiges Netz gedacht. Sobald der Port darüber
  hinaus erreichbar ist, `ADMIN_USER`/`ADMIN_PASSWORD` in `.env` setzen -
  dann verlangt die App HTTP-Basic-Auth. Alternativ/zusätzlich einen
  Reverse-Proxy mit OAuth davorsetzen.
- Ziel-IPs/CIDRs und Dienst-Protokolle/-Ports werden serverseitig validiert
  (`ipaddress`-Modul bzw. Whitelist), bevor sie in das generierte
  iptables-Script einfließen - das schließt Command-Injection über das
  Formular. Trotzdem gilt: Wer Zugriff auf die Web-UI hat, kann beliebige
  iptables-Regeln auf dem Zielserver erzeugen - Zugriff entsprechend
  einschränken (siehe oben).
- Generierte Client-Configs/-Skripte ("Client bereitstellen") enthalten den
  Public Key und Endpoint des Servers, aber **keinen** privaten Schlüssel
  der App oder anderer Peers - der private Schlüssel des neuen Clients wird
  ausschließlich lokal auf dessen eigenem Gerät erzeugt.

## Troubleshooting

**Dashboard zeigt "Konnte Status nicht abrufen" (EXEC_MODE=ssh):**
- Prüfen, ob der WG-Tunnel steht: `docker compose exec wg-acl-manager wg show wg0`
- Prüfen, ob der SSH-Key auf dem Zielserver hinterlegt ist (Schritt 5)
- Prüfen, ob `WG_SERVER_TUNNEL_IP` in `.env` mit der tatsächlichen Tunnel-IP
  des Zielservers übereinstimmt (Standard: `10.250.0.1`)

**Dashboard zeigt "Konnte Status nicht abrufen" (EXEC_MODE=local):**
- Prüfen, ob `TARGET_WG_INTERFACE` wirklich dem echten Interface-Namen auf
  diesem Host entspricht: `wg show` (auf dem Host, außerhalb des Containers)
- Prüfen, ob der Container tatsächlich mit `network_mode: host` läuft:
  `docker inspect wg-acl-manager --format '{{.HostConfig.NetworkMode}}'`
  sollte `host` ausgeben
- Prüfen, ob `cap_add: NET_ADMIN` gesetzt ist (siehe `docker-compose.local.yml`)

**Namensspalte im WireGuard-Status zeigt nur "-" (EXEC_MODE=local):**
- Prüfen, ob der Bind-Mount aktiv ist:
  `docker compose -f docker-compose.local.yml exec wg-acl-manager cat /etc/wireguard/wg0.conf`
  sollte die echte Host-Config zeigen, nicht leer/Fehler sein
- Falls das Volume erst nachträglich zu `docker-compose.local.yml` hinzugefuegt
  wurde: Container einmal neu erstellen (Volume-Aenderungen wirken erst nach
  einem `up -d`, nicht nach einem reinen `restart`):
  `docker compose -f docker-compose.local.yml up -d`
- Prüfen, ob im jeweiligen `[Peer]`-Block wirklich die **erste** Zeile ein
  `#Name`-Kommentar ist (nicht erst nach `PublicKey`/`AllowedIPs`)

**Regeln werden gespeichert, aber "Anwenden fehlgeschlagen":**
- EXEC_MODE=ssh: Fehlermeldung aus der Flash-Message zeigt meist direkt die
  SSH-/iptables-Fehlerausgabe. Häufigste Ursache: SSH-Key noch nicht in
  `authorized_keys`, oder `WG_SERVER_SSH_USER` hat keine Root-/sudo-Rechte
  für `iptables`.
- EXEC_MODE=local: Fehlermeldung zeigt die iptables-Fehlerausgabe direkt.
  Häufigste Ursache: Container läuft nicht mit `NET_ADMIN`/`network_mode:
  host`, oder läuft nicht als root im Container.

## Entwicklung & Tests

Im Container läuft die App produktiv über `waitress` (WSGI). Für lokale
UI-Iteration ohne Docker/echten WG-Server reicht der Flask-Dev-Server
(siehe `CLAUDE.md`).

Unit-Tests (v.a. für die iptables-Script-Generierung und Eingabevalidierung)
liegen unter `tests/`:

```bash
pip install -r requirements-dev.txt
pytest
```

CI (`.github/workflows/tests.yml`) führt diese Tests bei jedem Push aus.
