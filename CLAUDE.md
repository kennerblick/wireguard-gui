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
app/app.py          - komplette Anwendungslogik (Routen, DB, SSH-Aufrufe,
                       iptables-Script-Generierung)
app/templates/       - Jinja2-Templates (base, index=Dashboard, services)
app/static/style.css - Styling
entrypoint.sh         - Container-Start: WG-Keypair + SSH-Keypair erzeugen
                       (persistiert unter /data), wg0 hochfahren, App starten
Dockerfile           - Basis-Image + Systempakete (wireguard-tools,
                       openssh-client) + Python-Deps
docker-compose.yml   - lokale Deployment-Definition
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

## Noch nicht umgesetzt / bekannte Lücken

Das hier ist der eigentliche Auftrag für diese Session - bitte in dieser
Reihenfolge angehen (grob nach Wichtigkeit für Produktivbetrieb):

1. **Keine Authentifizierung der Web-UI.** Aktuell nur für "lokaler Rechner,
   vertrauenswürdiges Netz" gedacht. Sinnvoll wäre mindestens ein simpler
   Login (Flask-Login o.ä. oder Basic-Auth per `.env`-Passwort), damit man
   den Port auch mal in ein gemeinsames Netz exponieren könnte.
2. **Flask-Dev-Server statt Produktions-WSGI-Server.** `app.run()` in
   `app.py` sollte durch `gunicorn`/`waitress` ersetzt werden (im
   Dockerfile/Entrypoint entsprechend anpassen).
3. **Keine automatisierten Tests.** Insbesondere `build_apply_script()` und
   `build_remove_script()` sollten Unit-Tests bekommen (reine String-
   Generierung, leicht testbar ohne echten SSH-Zugriff) - Regressionen bei
   der iptables-Regel-Syntax sind hier besonders schmerzhaft, weil Fehler
   erst live auf einem Produktivserver auffallen.
4. **`ssh_run()` hat keinen Retry/Backoff** und keinen Verbindungs-Pool -
   bei vielen Regeln/Clients wird für jede Aktion eine neue SSH-Verbindung
   aufgebaut. Für kleine Setups (< 20 Clients) unkritisch, könnte aber bei
   `apply_all` mit vielen Clients spürbar langsam werden. Ggf. `ControlMaster`/
   `ControlPersist` in den SSH-Optionen nutzen, um eine Verbindung
   wiederzuverwenden.
5. **Keine Validierung von Nutzereingaben** über simple SQL-Parameter-
   Bindung hinaus - `dest_ip` und Service-Namen werden nicht auf Plausibilität
   geprüft (z.B. ob `dest_ip` wirklich eine gültige IP/CIDR ist). Da der Wert
   direkt in ein generiertes Shell-Script einfließt (`build_apply_script`),
   ist das ein potenzielles Command-Injection-Risiko, wenn die Web-UI mal
   nicht mehr nur vom Admin selbst bedient wird. **Sollte vor jeder
   Mehrbenutzer-Nutzung behoben werden** - IP/CIDR-Validierung (z.B. mit
   Pythons `ipaddress`-Modul) und Whitelisting erlaubter Zeichen für
   Service-Namen ergänzen.
6. **Kein Wegräumen verwaister Chains.** Wenn ein Client-Datensatz direkt in
   der SQLite-DB gelöscht wird (statt über die "Entfernen"-Aktion in der
   UI), bleibt seine iptables-Chain auf dem Zielserver zurück. Ein
   Abgleichs-/Cleanup-Mechanismus (z.B. beim Start alle `WGACL_*`-Chains
   ohne zugehörigen DB-Eintrag auflisten und zum Löschen vorschlagen) wäre
   sinnvoll.
7. **Bulk-Import fehlt.** Für Erstbefüllung bei einem bestehenden WG-Netz
   mit vielen Peers wäre ein CSV-Import (Client-Liste) hilfreich, statt
   jeden einzeln über das Formular anzulegen.
8. **`fetch_wg_status()` parsed `wg show ... dump` recht simpel** (Split auf
   Tabs, erwartet genau 7+ Felder) - bei Peers ohne Endpoint (nie verbunden)
   kann das Format leicht abweichen; sollte robuster gegen fehlende Felder
   gemacht werden.

## Lokales Testen ohne echten WG-Server

Für schnelle UI-Iteration lässt sich die App auch direkt mit Python starten
(ohne Docker, ohne echten WireGuard-Tunnel) - `ssh_run()` schlägt dann
einfach fehl (Timeout/Connection refused), das Dashboard zeigt einen
Fehlerzustand, aber CRUD auf Clients/Services/Regeln funktioniert trotzdem,
da diese nur in SQLite landen:

```bash
cd app
pip install flask
ISURFER_WG_IP=127.0.0.1 python app.py
```

Für einen echten End-to-End-Test braucht es einen echten Linux-Server mit
WireGuard + iptables, zu dem der Test-Rechner selbst eine WG-Verbindung
aufbauen kann (z.B. eine Wegwerf-VM).
