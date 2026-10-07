#!/bin/sh
# =============================================================================
# Docker-Secrets als Umgebungsvariablen (Swarm, 06.10.2026)
# -----------------------------------------------------------------------------
# Swarm reicht Secrets als Dateien unter /run/secrets/<name> herein. VectiScan
# liest aber nur Umgebungsvariablen (api, scan-worker, report-worker) -- ohne
# diese Bruecke muessten alle drei umgebaut werden, nur weil sich das Ziel des
# Deploys geaendert hat.
#
#   /run/secrets/database_url   ->  DATABASE_URL
#   /run/secrets/redis_url      ->  REDIS_URL
#
# Die Datei liegt NICHT im Image, sondern kommt als Swarm-Config herein
# (stack.yml, CONFIG_FILES in ci/swarm.yml). Die Images bleiben damit dieselben
# wie auf docker02, und dort aendert sich nichts.
#
# Zwei Regeln:
#   - Eine schon gesetzte Variable gewinnt; das Secret ueberschreibt nichts.
#   - Ein Secret mit genau dem Wert "-" gilt als NICHT gesetzt. Docker-Secrets
#     duerfen nicht leer sein, die optionalen Schluessel (SHODAN_API_KEY & Co.)
#     sind es aber, und die Anwendung unterscheidet "leer" von "gesetzt".
#
# Danach `exec` auf den Startbefehl aus `command` in stack.yml, damit SIGTERM
# direkt beim Prozess ankommt.
# =============================================================================
set -e
for f in /run/secrets/*; do
  [ -f "$f" ] || continue
  name=$(basename "$f" | tr '[:lower:]-' '[:upper:]_')
  wert=$(cat "$f")
  [ "$wert" = "-" ] && continue
  eval "cur=\${$name:-}"
  if [ -z "$cur" ]; then
    export "$name=$wert"
  fi
done
exec "$@"
