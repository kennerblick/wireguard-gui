"""WSGI-/Dev-Einstiegspunkt.

Die eigentliche Anwendung lebt im Package wg_acl_manager/ (siehe dessen
__init__.py fuer die Architekturuebersicht). Diese Datei bleibt bewusst ein
duenner Shim, damit sich am Aufruf-Vertrag nichts aendert:
"waitress-serve app:app" (Container) und "python app.py" (lokale
Entwicklung) funktionieren unveraendert weiter.
"""

from wg_acl_manager import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
