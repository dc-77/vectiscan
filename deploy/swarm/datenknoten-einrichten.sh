#!/usr/bin/env bash
# =============================================================================
# Rolle und Datenbank fuer VectiScan auf dem Datenknoten (Swarm, 06.10.2026)
# -----------------------------------------------------------------------------
# Aufruf auf docker-share01, nach `git clone` des Repositorys:
#
#   bash deploy/swarm/datenknoten-einrichten.sh test     # Instanz 5432
#   bash deploy/swarm/datenknoten-einrichten.sh prod     # Instanz 5433
#   bash deploy/swarm/datenknoten-einrichten.sh prod 80  # nach Anhebung von max_connections
#
# ACHTUNG: 5432 ist vectigal_test, 5433 vectigal_prod -- anders herum als im
# Planungsdokument.
#
# Legt die Rolle `vectiscan` und die Datenbank `vectiscan` an, falls sie fehlen,
# und fragt das Passwort ueber \password ab: es steht damit weder in der
# Befehlszeile noch in der Shell-Historie. Erweiterungen braucht VectiScan
# keine (gen_random_uuid ist seit PostgreSQL 13 eingebaut); die Migrationen
# beim Start der api brauchen aber Eigentuemerrechte (ALTER TABLE, Trigger,
# Funktionen in plpgsql), deshalb gehoert die Datenbank der Rolle.
#
# Die Rolle bekommt eine Verbindungsgrenze (Vorgabe Test 40, Prod 55; 55 passt
# in die 100 Verbindungen von 5433 neben den 37 vom 06.10.2026, 80 erst nach
# einer Anhebung von max_connections).
# VectiScan verbindet am Pooler vorbei und kommt in Prod in Spitzen auf 52 bis
# 73 Verbindungen (docs/UMZUG-swarm.md, Abschnitt 1.1). Ohne Grenze naehme ein
# Ausreisser der ganzen Instanz die Verbindungen weg, also allen Anwendungen
# darauf; mit Grenze scheitert nur VectiScan selbst. Danach zeigt das Skript,
# wie voll die Instanz ist.
# =============================================================================
set -euo pipefail

case "${1:-}" in
  test) PORT=5432; GRENZE="${2:-40}" ;;
  prod) PORT=5433; GRENZE="${2:-55}" ;;
  *) echo "Aufruf: $0 test|prod [verbindungsgrenze]"; exit 2 ;;
esac
case "$GRENZE" in
  ''|*[!0-9]*) echo "Verbindungsgrenze muss eine Zahl sein: '$GRENZE'"; exit 2 ;;
esac

psql_su() { sudo -u postgres psql -p "$PORT" -v ON_ERROR_STOP=1 "$@"; }

echo "== 1. Instanz auf Port $PORT =="
psql_su -Atc "SELECT current_setting('cluster_name', true) || '  ' || version()"

echo "== 2. Rolle vectiscan =="
if [ "$(psql_su -Atc "SELECT 1 FROM pg_roles WHERE rolname = 'vectiscan'")" = "1" ]; then
  echo "  vorhanden, Passwort bleibt"
else
  psql_su -c "CREATE ROLE vectiscan LOGIN"
  echo "  angelegt. Jetzt das Passwort setzen (zweimal eingeben):"
  psql_su -c "\\password vectiscan"
fi

psql_su -c "ALTER ROLE vectiscan CONNECTION LIMIT $GRENZE"
echo "  Verbindungsgrenze: $(psql_su -Atc "SELECT rolconnlimit FROM pg_roles WHERE rolname = 'vectiscan'")"

echo "== 3. Datenbank vectiscan =="
if [ "$(psql_su -Atc "SELECT 1 FROM pg_database WHERE datname = 'vectiscan'")" = "1" ]; then
  echo "  vorhanden, Eigentuemer: $(psql_su -Atc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = 'vectiscan'")"
else
  psql_su -c "CREATE DATABASE vectiscan OWNER vectiscan"
  echo "  angelegt"
fi
echo "  Tabellen: $(psql_su -d vectiscan -Atc "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'")"

echo "== 4. Verbindungen der Instanz =="
psql_su -Atc "SELECT 'max_connections ' || current_setting('max_connections') || ', belegt ' || count(*) FROM pg_stat_activity"
psql_su -Atc "SELECT '  ' || coalesce(usename, '(System)') || ': ' || count(*) FROM pg_stat_activity GROUP BY usename ORDER BY count(*) DESC"

echo "== 5. pg_hba: wer darf auf die Datenbank vectiscan? =="
psql_su -Atc "SELECT '  ' || type || ' ' || array_to_string(database, ',') || ' ' || array_to_string(user_name, ',') || ' ' || coalesce(address, '') || ' ' || auth_method FROM pg_hba_file_rules WHERE type <> 'local' AND ('all' = ANY(database) OR 'vectiscan' = ANY(database))"
