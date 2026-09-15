# WireGuard ACL Manager - Projektkontext für Claude Code

## Was das ist

Lokaler Docker-Container mit Web-GUI (Flask + SQLite), der verwaltet,
welcher WireGuard-Peer auf einem Hub-and-Spoke-WireGuard-Server (z.B.
`isurfer.de`) auf welche Ziele/Dienste zugreifen darf. Der Container baut
selbst einen WireGuard-Tunnel zum Zielserver auf und verwaltet dort per SSH
gezielt `iptables`-Regeln (eine eigene Chain pro eingeschränktem Client,
Sprung dorthin aus `DOCKER-USER` bzw. `FORWARD`).

Entstanden aus einer konkreten Situation: Ein Admin hat ein Hub-and-Spoke-
WireGuard-Netz mit ~15 Peers (Server, Router, Mitarbeiter-PCs) auf einem
Ubuntu-Server mit Docker betrieben, brauchte aber granularere Kontrolle,
welcher Peer wohin darf, statt der bisherigen Alles-oder-nichts-Regel.

## Stack

- **Backend:** Python 3.12, Flask (kein ORM, rohes `sqlite3`)
- **Frontend:** Server-seitig gerendertes Jinja2, kein JS-Framework, ein
  eigenes CSS (`app/static/style.css`), bewusst minimalistisch gehalten
- **Deployment:** Ein einzelner Docker-Container (`docker-compose.yml`),
  läuft lokal beim Admin, nicht auf dem verwalteten Server selbst
- **Kommunikation zum Zielserver:** WireGuard-Tunnel (nur zur Ziel-IP, nicht
  zum ganzen Subnetz) + SSH mit einem beim ersten Start generierten
  Ed25519-Schlüssel

## Architektur in Kürze

```
app/app.py           - komplette Anwendungslogik (Routen, DB, SSH-Aufrufe,
                       iptables-Script-Generierung, Basic-Auth, Validierung)
app/templates/       - Jinja2-Templates (base, index=Dashboard, services,
                       maintenance=verwaiste Chains)
app/static/style.css - Styling
tests/               - pytest-Suite fuer Script-Generierung, Validierung,
                       Hook-Erkennung (kein echter SSH-/WG-Zugriff noetig)
.github/workflows/   - CI (pytest bei jedem Push)
entrypoint.sh         - Container-Start: WG-Keypair + SSH-Keypair erzeugen
                       (persistiert unter /data), wg0 hochfahren,
                       App per waitress starten
Dockerfile           - Basis-Image + Systempakete (wireguard-tools,
                       openssh-client) + Python-Deps
docker-compose.yml   - lokale Deployment-Definition
requirements-dev.txt - zusaetzliche Dev-/Test-Abhaengigkeiten (pytest)
.env.example         - Konfigurationsvorlage
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
  in `ssh_run()` - `apply_all` mit vielen Clients baut nicht mehr pro Aktion
  eine neue SSH-Verbindung auf.
- **Aufräumen verwaister Chains**: neue Seite "Wartung" listet `WGACL_*`-
  Chains auf dem Zielserver ohne zugehörigen DB-Client auf und kann sie
  gezielt entfernen (`list_remote_wgacl_chains()`,
  `/maintenance/cleanup`).
- **`fetch_wg_status()`** überspringt Zeilen mit unerwartetem Format statt
  mit einem Exception abzustürzen.
- **Unit-Tests** (`tests/`, `pytest`) für Script-Generierung
  (`build_apply_script`/`build_remove_script`), Eingabevalidierung und
  Hook-Erkennung; CI via `.github/workflows/tests.yml`.

## Noch nicht umgesetzt / bekannte Lücken

Verbleibend, in etwa nach Wichtigkeit sortiert:

1. **Kein CSRF-Schutz.** Alle State-ändernden Routen sind reine POST-Forms
   ohne Token; die Basic-Auth schützt vor fremdem Zugriff, aber nicht vor
   Cross-Site-Request-Forgery aus einem Browser, der bereits angemeldet ist.
   Bei Bedarf `flask-wtf`/eigenes Double-Submit-Token ergänzen.
2. **`ssh_run()` hat keinen Retry/Backoff** bei transienten Netzwerkfehlern
   (nur die Verbindungswiederverwendung wurde ergänzt, kein Retry).
3. **Bulk-Import fehlt.** Für Erstbefüllung bei einem bestehenden WG-Netz
   mit vielen Peers wäre ein CSV-Import (Client-Liste) hilfreich, statt
   jeden einzeln über das Formular anzulegen.
4. **Login ist reine Basic-Auth ohne Rate-Limiting/Lockout** - für ein rein
   lokales/vertrauenswürdiges Netz ausreichend, für Exposition darüber
   hinaus wäre ein härterer Login-Mechanismus (z.B. hinter einem
   Reverse-Proxy mit OAuth) vorzuziehen.

## Lokales Testen ohne echten WG-Server

Für schnelle UI-Iteration lässt sich die App auch direkt mit Python starten
(ohne Docker, ohne echten WireGuard-Tunnel) - `ssh_run()` schlägt dann
einfach fehl (Timeout/Connection refused), das Dashboard zeigt einen
Fehlerzustand, aber CRUD auf Clients/Services/Regeln funktioniert trotzdem,
da diese nur in SQLite landen:

```bash
cd app
pip install flask waitress
ISURFER_WG_IP=127.0.0.1 python app.py
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
