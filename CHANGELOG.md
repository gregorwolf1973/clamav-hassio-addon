# Changelog

## 1.0.13

- Fix: Die Option `log_level` wird jetzt tatsächlich ausgewertet. `run.sh`
  setzt den bashio-Log-Level und exportiert `LOG_LEVEL`; Web-GUI,
  Scheduler und Scanner konfigurieren daraus das Python-Logging. Ab
  `warning` entfallen die Zugriffszeilen der Weboberfläche, bei
  `debug`/`trace` protokollieren zusätzlich clamd und freshclam
  ausführlich.
- Doku: `web_port` ändert nur den Port im Container - das
  Home-Assistant-Panel (Ingress) liegt fest auf 8200, ein anderer Wert
  macht die Oberfläche unerreichbar (Optionsbeschreibung und DOCS).
- Doku: `max_file_size_mb` wirkt nur im Modus `on_demand` ohne Neustart,
  im Modus `always` steht der Wert in der `clamd.conf` und erfordert einen
  Neustart.
- Doku: veralteten Hinweis zu `\\.` in den YAML-Beispielen entfernt,
  Logging-Abschnitt ergänzt, armv7-Hinweis an die `arch`-Liste angepasst.
- MIT-LICENSE-Datei ergänzt (das README-Badge verlinkte bisher ins Leere).

## 1.0.11

- Fix: Absicherung gegen einen Startabsturz. Beim Binden des Webservers
  fragt Python den Hostnamen per Reverse-DNS ab. Liefert der DNS-Server
  einen Namen, der kein gültiges UTF-8 ist, warf das einen
  UnicodeDecodeError und das Addon startete nicht (Supervisor-Status
  "error"). Die Abfrage ist jetzt gekapselt.

