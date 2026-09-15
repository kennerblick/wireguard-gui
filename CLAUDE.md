# WireGuard ACL Manager - Projektkontext für Claude Code

## Was das ist

Docker-Container mit Web-GUI (Flask + SQLite), der verwaltet, welcher
WireGuard-Peer auf einem Hub-and-Spoke-WireGuard-Server auf welche
Ziele/Dienste zugreifen darf. Erzeugt/entfernt dafür gezielt
`iptables`-Regeln (eine eigene Chain pro eingeschränktem Client, Sprung
dorthin aus `DOCKER-USER` bzw. `FORWARD`) - je nach `EXEC_MODE` entweder
per SSH über einen selbst aufgebauten WG-Tunnel, oder direkt lokal.

Entstanden aus einer konkreten Situation: Ein Admin hat ein Hub-and-Spoke-
WireGuard-Netz mit ~15 Peers (Server, Router, Mitarbeiter-PCs) auf einem
Ubuntu-Server mit Docker betrieben, brauchte aber granularere Kontrolle,
welcher Peer wohin darf, statt der bisherigen Alles-oder-nichts-Regel.

## Zwei Ausfuehrungsmodi (`EXEC_MODE`)

Alle iptables-Aenderungen laufen ueber die eine Funktion
`run_on_target(script)` in `app/app.py`, die je nach `EXEC_MODE` dispatcht:

- **`ssh`** (Standard, urspruengliches Design): Container laeuft auf einer
  **separaten** Maschine (z.B. beim Admin), baut selbst einen WireGuard-
  Tunnel zum Zielserver auf (nur zu dessen Tunnel-IP, nicht zum ganzen
  Subnetz - Least Privilege) und fuehrt die generierten Bash/iptables-
  Scripts per SSH mit einem beim ersten Start generierten Ed25519-Schluessel
  aus. Deployment: `docker-compose.yml`.
- **`local`**: Container laeuft **direkt auf dem WireGuard-Server selbst**.
  `run_on_target()` fuehrt das Script per `subprocess.run(["bash", "-c",
  script])` direkt im Container aus - kein Tunnel, kein SSH-Key. Braucht
  `network_mode: host` + `cap_add: NET_ADMIN`, damit der Container dieselben
  Netzwerk-Namespaces wie der Host sieht (`iptables`/`wg show` wirken sonst
  nur auf den isolierten Container-Netzwerk-Namespace). Deployment:
  `docker-compose.local.yml`. Da Container-Neustart hier typischerweise mit
  Host-Reboot zusammenfaellt, baut `reapply_all_on_startup()` beim Start
  alle Client-Regeln aus der DB neu auf (Ersatz fuer eine
  `netfilter-persistent`-Abhaengigkeit fuer die WGACL-Regeln selbst).

Trade-off `local`: einfacheres Deployment (keine zweite Maschine, kein
Tunnel/SSH-Setup), aber der Container sieht dafuer das komplette
Host-Netzwerk statt nur einer einzelnen Tunnel-IP - Basic-Auth ist hier
praktisch Pflicht (siehe README, Sicherheitshinweise).

## Stack

- **Backend:** Python 3.12, Flask (kein ORM, rohes `sqlite3`)
- **Frontend:** Server-seitig gerendertes Jinja2, kein JS-Framework, ein
  eigenes CSS (`app/static/style.css`), bewusst minimalistisch gehalten
- **Deployment:** Ein einzelner Docker-Container, zwei Compose-Varianten
  (`docker-compose.yml` fuer `EXEC_MODE=ssh`, `docker-compose.local.yml`
  fuer `EXEC_MODE=local`)
- **Kommunikation zum Zielserver:** je nach Modus WireGuard-Tunnel (nur zur
  Ziel-IP) + SSH mit generiertem Ed25519-Schluessel, oder direkte lokale
  Ausfuehrung (siehe oben)

## Architektur in Kürze

```
app/app.py              - komplette Anwendungslogik (Routen, DB,
                          run_on_target()=SSH- oder lokale Ausfuehrung,
                          iptables-Script-Generierung, Basic-Auth, Validierung)
app/templates/          - Jinja2-Templates (base, index=Dashboard, services,
                          maintenance=verwaiste Chains + Firewall-Regeln,
                          netzplan=Graph + Berechtigungsmatrix,
                          provision=Client bereitstellen)
app/static/style.css    - Styling
tests/                  - pytest-Suite fuer Script-Generierung, Validierung,
                          Hook-Erkennung (kein echter SSH-/WG-Zugriff noetig)
.github/workflows/      - CI (pytest bei jedem Push)
entrypoint.sh            - Container-Start: bei EXEC_MODE=ssh WG-Keypair +
                          SSH-Keypair erzeugen (persistiert unter /data),
                          wg0 hochfahren; bei EXEC_MODE=local direkt
                          waitress starten. Immer: App per waitress starten
Dockerfile              - Basis-Image + Systempakete (wireguard-tools,
                          openssh-client, iptables) + Python-Deps
docker-compose.yml      - Deployment-Definition fuer EXEC_MODE=ssh
docker-compose.local.yml - Deployment-Definition fuer EXEC_MODE=local
                          (network_mode: host, kein WG-Tunnel/SSH-Key)
requirements-dev.txt    - zusaetzliche Dev-/Test-Abhaengigkeiten (pytest)
.env.example            - Konfigurationsvorlage (beide Modi)
```

**Datenmodell** (SQLite, `/data/db/wgacl.db`):
- `clients` (wg_ip, label, restricted-Flag)
- `services` (name, protocol, port; `is_builtin`-Flag schützt Standarddienste vor Löschung)
- `rules` (client_id, dest_ip, service_id) - dest_ip="any" bedeutet kein Ziel-Filter
- `apply_log` (Historie der SSH-Anwendungsversuche, Erfolg/Fehlertext)

**Kernfunktion `build_apply_script()`** in `app/app.py`: generiert pro
Client ein idempotentes Bash/iptables-Script (eigene Chain `WGACL_<ip>`,
`ACCEPT`-Regeln pro `rules`-Eintrag, abschließendes `DROP`, Sprung-Regel im
erkannten Hook-Punkt). `detect_hook_chain()` unterscheidet automatisch
zwischen Servern mit Docker (`DOCKER-USER`-Chain vorhanden) und ohne
(direkt `FORWARD`).

## Bereits umgesetzt

- CRUD für Clients, Services, Regeln über die Web-UI
- Live-Anwenden bei jeder Änderung (kein separater "Speichern"-Schritt nötig)
- Dashboard zeigt echten `wg show <interface> dump`-Status vom Zielserver
- Generalisiert (nicht mehr hart auf eine Umgebung zugeschnitten):
  - `TARGET_WG_INTERFACE` konfigurierbar (Server nutzen nicht alle `wg0`)
  - Automatische Docker- vs. Nicht-Docker-Erkennung für den Hook-Punkt
  - `ip_forward`-Status wird geprüft und im Dashboard als Warnung angezeigt
  - Persistenz (`netfilter-persistent`) wird versucht, aber nicht vorausgesetzt
- **Optionale HTTP-Basic-Auth** (`ADMIN_USER`/`ADMIN_PASSWORD` in `.env`) -
  ohne gesetzte Werte bleibt die App wie bisher offen (mit Startup-Warnung im
  Log), damit bestehende Deployments nicht brechen.
- **Produktions-WSGI-Server**: `entrypoint.sh` startet die App im Container
  über `waitress-serve` statt des Flask-Dev-Servers; `app.run()` bleibt nur
  für lokale Entwicklung (`python app.py`) erhalten.
- **Eingabevalidierung gegen Command-Injection**: `validate_dest_ip()`
  (Modul `ipaddress`) prüft jede Ziel-IP/CIDR vor dem Insert; `add_service()`
  validiert Protokoll gegen eine Whitelist (`tcp`/`udp`/`all`) und Namen
  gegen eine Zeichen-Whitelist, bevor die Werte in das per SSH ausgeführte
  iptables-Script einfließen.
- **SSH-Verbindungswiederverwendung** über `ControlMaster`/`ControlPersist`
  in `run_on_target()` (EXEC_MODE=ssh) - `apply_all` mit vielen Clients baut
  nicht mehr pro Aktion eine neue SSH-Verbindung auf.
- **Lokaler Ausfuehrungsmodus** (`EXEC_MODE=local`): `run_on_target()` kann
  das generierte Script statt per SSH auch direkt im Container ausfuehren,
  fuer den Fall, dass wg-acl-manager auf dem WG-Server selbst laeuft (kein
  eigener Tunnel, kein SSH-Key noetig). Braucht `network_mode: host` +
  `cap_add: NET_ADMIN` (`docker-compose.local.yml`). Baut beim Start ueber
  `reapply_all_on_startup()` alle Client-Regeln aus der DB neu auf, da ein
  Container-Neustart hier meist mit einem Host-Reboot zusammenfaellt.
- **Aufräumen verwaister Chains**: neue Seite "Wartung" listet `WGACL_*`-
  Chains auf dem Zielserver ohne zugehörigen DB-Client auf und kann sie
  gezielt entfernen (`list_remote_wgacl_chains()`,
  `/maintenance/cleanup`).
- **`fetch_wg_status()`** überspringt Zeilen mit unerwartetem Format statt
  mit einem Exception abzustürzen.
- **Peer-Namen aus der WireGuard-Config**: `fetch_wg_peers_from_config()`
  liest `/etc/wireguard/<interface>.conf` auf dem Ziel und wertet je
  `[Peer]`-Block dessen erste Zeile als Namens-Kommentar (`#Name`) aus;
  `peer_lookup_maps()` baut daraus `pubkey->Name`/`ip->Name`. Wird im
  Dashboard (Name-Spalte im WireGuard-Status) und im Netzplan verwendet.
  Fehlt der Kommentar, fällt die UI auf IP bzw. Client-Bezeichnung zurück.
  **`peer_own_ip(peer)`** ermittelt die eigene Tunnel-IP eines Peers: bei
  einem gewöhnlichen Peer (`AllowedIPs = ip/32`) einfach die erste Adresse
  aus `AllowedIPs`, bevorzugt aber eine explizite `#IP: x.x.x.x`-Kommentarzeile
  im `[Peer]`-Block, falls vorhanden. Das ist notwendig für Peers mit
  weiterreichendem Zugriff (`AllowedIPs` deckt ein ganzes Subnetz ab, z.B.
  ein Admin-Rechner mit Zugriff auf alle anderen Peers) - dort wäre "erste
  Adresse aus AllowedIPs" sonst die Netzwerk-Adresse (z.B. `10.250.0.0` bei
  `AllowedIPs = 10.250.0.0/24`), nicht die tatsächliche eigene IP. Bug
  gefunden beim ersten "Peers importieren" auf einer echten Config mit
  genau so einem Peer. Alle Stellen, die frueher `allowed_ips` selbst
  parsten (`peer_lookup_maps()`, `import_peers_from_config()`,
  `suggest_free_ip()`), nutzen jetzt einheitlich `peer_own_ip()`.
- **Netzplan-Seite** (`/netzplan`): SVG-Graph (Knoten kreisförmig
  angeordnet, `build_netzplan_data()`) zeigt erlaubte Verbindungen als
  Linien; Hover zeigt die zusammengefassten erlaubten Dienste (reines
  `<title>`-freies Tooltip per JS, kein zusätzliches JS-Framework).
  Uneingeschränkte Clients werden nur farblich hervorgehoben (gelber
  Rahmen), ohne Linien zu allen anderen Peers zu zeichnen. Darunter eine
  Quick-Toggle-Matrix (`/netzplan/permissions/set`): Dropdown mit
  eingeschränkten Clients links, Mehrfachauswahl aller bekannten Peers
  rechts (Checkboxen, per JS aus eingebettetem JSON befüllt und je nach
  gewähltem Client vorbelegt). Verwaltet ausschließlich Regeln mit dem
  Dienst "Alle Ports" (`get_all_ports_service_id()`,
  `diff_target_sets()`) - feinere, dienstspezifische Regeln bleiben davon
  unberührt und werden weiter über die bestehende Rule-Formular im
  Dashboard verwaltet.
- **Unit-Tests** (`tests/`, `pytest`) für Script-Generierung
  (`build_apply_script`/`build_remove_script`), Eingabevalidierung und
  Hook-Erkennung; CI via `.github/workflows/tests.yml`.
- **Peers aus Config importieren** (`import_peers_from_config()`,
  `/clients/import`): legt fuer WireGuard-Peers, die noch kein Client in
  dieser App sind, einen neuen Client-Datensatz an - **eingeschraenkt, ohne
  Regeln** (derselbe Default wie beim manuellen Hinzufuegen), macht also
  bewusst KEINE Annahme ueber tatsaechliche Zugriffsrechte. Grund: die
  urspruengliche Annahme "kein Eintrag = volles Mesh" gilt nicht fuer jedes
  Setup - manche Deployments erlauben Peers standardmaessig nur den Zugriff
  auf den Hub, nicht untereinander. Ändert nichts an der Firewall (kein
  `apply_client()`-Aufruf beim Import).
- **Firewall-Regeln (Ist-Zustand)** auf der Wartungsseite: liest
  `iptables -S DOCKER-USER` und `iptables -S FORWARD` vom Ziel
  (`parse_iptables_rules()`, `annotate_ips()`, `build_ip_label_map()`),
  read-only. Einfache `-s`/`-d`/`-p`/`--dport`-Regeln (auch die von dieser
  App selbst erzeugten `WGACL_*`-Sprungregeln) werden in eine lesbare
  Tabelle uebersetzt, IPs mit dem bekannten Peer-Namen annotiert. Regeln mit
  Negation (`!`) oder Modulen (`-m ...`) werden bewusst NICHT interpretiert
  (nur Rohtext) - das koennte sonst falsche Zugriffs-Aussagen suggerieren.
  Existiert, damit ein Admin den echten Ist-Zustand nachvollziehen kann,
  bevor er ihn in dieser App nachbildet.
- **Client bereitstellen** (`/provision`, `/provision/script`,
  `/provision/register`): Zwei-Schritte-Assistent fuer einen komplett neuen
  WireGuard-Peer, im Format der bestehenden `setup-wg-client.sh`/`.ps1`/
  MikroTik-`.rsc`-Skripte des Admins nachgebaut. **Sicherheitsdesign:** das
  WG-Schluesselpaar wird IMMER lokal auf dem neuen Client erzeugt (im
  generierten Skript selbst, per `wg genkey`/`wg.exe genkey`) - der private
  Schluessel verlaesst dieses Geraet nie und wird von wg-acl-manager weder
  gesehen noch gespeichert. Schritt 1 (`provision_script()`) generiert das
  Skript/die Config mit einer per `suggest_free_ip()` vorgeschlagenen freien
  IP (aus der [Interface]-Address der Ziel-Config abgeleitetes Subnetz,
  abzueglich aller Peers laut Config + Clients laut DB) sowie dem live
  ermittelten Server-Pubkey (`wg show <iface> public-key`) und
  `WG_SERVER_ENDPOINT`. Schritt 2 (`provision_register()`) nimmt den vom
  Skript ausgegebenen Public Key entgegen (`validate_wg_pubkey()` - Base64,
  32 Byte), registriert den Peer live per `wg set` UND persistent per
  Config-Anhang (`register_peer_on_target()`, idempotent via
  Pubkey-Grep-Check) und legt einen eingeschraenkten Client-Datensatz ohne
  Regeln an (macht bewusst keine Annahme ueber Zugriffsrechte, siehe oben).
  Optionale rsyslog-/MikroTik-Logging-Konfiguration im generierten Skript
  ueber `PROVISION_SYSLOG_PORT_LINUX`/`PROVISION_SYSLOG_PORT_MIKROTIK`
  (Host wird aus der Ziel-Config abgeleitet, keine eigene Env-Variable
  noetig).
- **Generische Variablennamen**: `ISURFER_*` (an einen konkreten Server
  gebunden) wurde zu `WG_SERVER_*` umbenannt
  (`WG_SERVER_PUBKEY`/`_ENDPOINT`/`_TUNNEL_IP`/`_SSH_USER`).
  `_env_with_legacy_fallback()` liest weiterhin die alten `ISURFER_*`-Namen,
  falls die neuen nicht gesetzt sind (mit Hinweis im Log) - bestehende
  `.env`-Dateien brechen dadurch nicht.

## Noch nicht umgesetzt / bekannte Lücken

Verbleibend, in etwa nach Wichtigkeit sortiert:

1. **Kein CSRF-Schutz.** Alle State-ändernden Routen sind reine POST-Forms
   ohne Token; die Basic-Auth schützt vor fremdem Zugriff, aber nicht vor
   Cross-Site-Request-Forgery aus einem Browser, der bereits angemeldet ist.
   Bei Bedarf `flask-wtf`/eigenes Double-Submit-Token ergänzen.
2. **`run_on_target()` hat keinen Retry/Backoff** bei transienten Netzwerkfehlern
   (nur die Verbindungswiederverwendung wurde ergänzt, kein Retry).
3. **Login ist reine Basic-Auth ohne Rate-Limiting/Lockout** - für ein rein
   lokales/vertrauenswürdiges Netz ausreichend, für Exposition darüber
   hinaus wäre ein härterer Login-Mechanismus (z.B. hinter einem
   Reverse-Proxy mit OAuth) vorzuziehen.

## Lokales Testen ohne echten WG-Server

Für schnelle UI-Iteration lässt sich die App auch direkt mit Python starten
(ohne Docker, ohne echten WireGuard-Tunnel) - `run_on_target()` schlägt dann
einfach fehl (Timeout/Connection refused), das Dashboard zeigt einen
Fehlerzustand, aber CRUD auf Clients/Services/Regeln funktioniert trotzdem,
da diese nur in SQLite landen:

```bash
cd app
pip install flask waitress
WG_SERVER_TUNNEL_IP=127.0.0.1 python app.py
```

Für einen echten End-to-End-Test braucht es einen echten Linux-Server mit
WireGuard + iptables, zu dem der Test-Rechner selbst eine WG-Verbindung
aufbauen kann (z.B. eine Wegwerf-VM).

## Unit-Tests

Reine Logik (Script-Generierung, Validierung, Hook-Erkennung) ist ohne
echten SSH-/WG-Zugriff testbar:

```bash
pip install -r requirements-dev.txt
pytest
```
