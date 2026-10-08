#!/bin/sh
# =============================================================================
# Datenumzug VectiScan, Teil 2: Import im Swarm (Job swarm:umzug:import)
# -----------------------------------------------------------------------------
# Laeuft im Job-Container (docker:28-cli, Alpine) auf dem Deploy-Runner, mit
# Environment vect-prod: DATABASE_URL ist die Prod-Datenbank auf 5433,
# MINIO_ACCESS_KEY der Schluessel vect-prod-app (Policy auf vect-prod-*).
#
# Die Datenbank muss LEER sein, also vor dem ersten swarm:deploy:prod: die
# api legt beim Start das Schema selbst an. Ist sie es nicht, bricht der Job
# ab, ohne etwas zu veraendern (docs/UMZUG-swarm.md, Abschnitt 3).
#
# Objekte laedt rclone aus den Alpine-Paketen hoch. mc gibt es nicht mehr
# zum Herunterladen (dl.min.io: 410 Gone seit Oktober 2026).
# Freigabe fuer das Einspielen in die Prod-Datenbank: Willi, 08.10.2026.
# =============================================================================
set -eu

REPO_DIR=${CI_PROJECT_DIR:?nur im CI-Job aufrufen}
ARBEIT="$REPO_DIR/umzug-arbeit"
BILD="${CI_REGISTRY_IMAGE}/umzug:${CI_PIPELINE_ID}"
PRAEFIX=vect-prod-

: "${UMZUG_SCHLUESSEL:?CI-Variable UMZUG_SCHLUESSEL fehlt}"
: "${DATABASE_URL:?DATABASE_URL fehlt, laeuft der Job mit environment vect-prod?}"
: "${MINIO_ACCESS_KEY:?MINIO_ACCESS_KEY fehlt}"
: "${MINIO_SECRET_KEY:?MINIO_SECRET_KEY fehlt}"
: "${DATENKNOTEN_ADDR:?Gruppenvariable DATENKNOTEN_ADDR fehlt}"
case "$DATABASE_URL" in
  *:5433/*) ;;
  *) echo "FEHLER: DATABASE_URL zeigt nicht auf 5433 (vect-prod). Abbruch, nichts veraendert." >&2; exit 1 ;;
esac
case "$MINIO_ACCESS_KEY" in
  vect-prod-*) ;;
  *) echo "FEHLER: MINIO_ACCESS_KEY ist nicht der Schluessel von vect-prod. Abbruch." >&2; exit 1 ;;
esac

apk add --no-cache openssl postgresql-client rclone >/dev/null
printf '%s datenknoten docker-share01\n' "$DATENKNOTEN_ADDR" >> /etc/hosts
q() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -At "$@"; }
export RCLONE_CONFIG_ZIEL_TYPE=s3
export RCLONE_CONFIG_ZIEL_PROVIDER=Minio
export RCLONE_CONFIG_ZIEL_ENDPOINT=http://datenknoten:9000
export RCLONE_CONFIG_ZIEL_ACCESS_KEY_ID="$MINIO_ACCESS_KEY"
export RCLONE_CONFIG_ZIEL_SECRET_ACCESS_KEY="$MINIO_SECRET_KEY"

echo "== 1. Ziel pruefen (noch nichts veraendert)"
q -c "SELECT current_database() || ' als ' || current_user || ' auf Port ' || current_setting('port')"
tabellen=$(q -c "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.relkind IN ('r','p') AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'")
if [ "$tabellen" -ne 0 ]; then
  echo "FEHLER: Die Prod-Datenbank hat schon $tabellen Tabellen. Lief swarm:deploy:prod schon?" >&2
  echo "        Dann gehoert sie erst geloescht und leer neu angelegt (Runbook, Abschnitt 3)." >&2
  exit 1
fi
# Alle Buckets auflisten darf vect-prod-app nicht (Policy nur auf
# vect-prod-*); einen davon anlegen schon, und den braucht es ohnehin.
rclone mkdir "ziel:${PRAEFIX}scan-rawdata"
echo "  Datenbank leer, MinIO auf dem Datenknoten erreichbar"

echo "== 2. Export ${BILD} laden und pruefen"
rm -rf "$ARBEIT"
mkdir -p "$ARBEIT"
cd "$ARBEIT"
echo "${CI_REGISTRY_PASSWORD}" | docker login "${CI_REGISTRY}" -u "${CI_REGISTRY_USER}" --password-stdin >/dev/null
docker pull -q "$BILD" >/dev/null \
  || { echo "FEHLER: ${BILD} gibt es nicht. Lief swarm:umzug:export in dieser Pipeline durch?" >&2; exit 1; }
# Ein Image aus scratch hat kein Programm; create braucht trotzdem einen Befehl.
cid=$(docker create "$BILD" kein-programm)
docker cp "$cid:/umzug/." .
docker rm "$cid" >/dev/null
docker rmi "$BILD" >/dev/null
docker logout "${CI_REGISTRY}" >/dev/null
for f in pruefsummen.txt zaehlung.txt objekte.txt db.sql.enc minio.tar.enc; do
  [ -s "$f" ] || { echo "FEHLER: $f fehlt im Image." >&2; exit 1; }
done
for f in db.sql minio.tar; do
  openssl enc -d -aes-256-cbc -pbkdf2 -iter 200000 -pass env:UMZUG_SCHLUESSEL -in "$f.enc" -out "$f"
  rm -f "$f.enc"
done
sha256sum -c pruefsummen.txt

echo "== 3. Dump einspielen (eine Transaktion)"
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 --single-transaction -q -f db.sql >/dev/null
rm -f db.sql

echo "== 4. Zeilen vergleichen"
q -f "$REPO_DIR/deploy/swarm/umzug-zaehlen.sql" > zaehlung-ziel.txt
if diff zaehlung.txt zaehlung-ziel.txt; then
  echo "  gleich: $(wc -l < zaehlung-ziel.txt) Tabellen"
else
  echo "FEHLER: Zeilenzahlen weichen ab (oben). swarm:deploy:prod NICHT starten." >&2
  exit 1
fi

echo "== 5. Bucket-Namen in reports auf ${PRAEFIX} umstellen"
# Die api liest den Bucket eines Berichts aus reports.minio_bucket.
q -c "UPDATE reports SET minio_bucket = '${PRAEFIX}' || minio_bucket WHERE minio_bucket NOT LIKE '${PRAEFIX}%'" | sed 's/^/  /'
q -c "SELECT minio_bucket || ' ' || count(*) FROM reports GROUP BY 1 ORDER BY 1" | sed 's/^/  /'

echo "== 6. MinIO-Objekte nach ${PRAEFIX}* auf dem Datenknoten"
mkdir -p minio
tar -xf minio.tar -C minio
rm -f minio.tar
while IFS='|' read -r b n; do
  ziel="${PRAEFIX}$b"
  rclone mkdir "ziel:$ziel"
  if [ "$n" -gt 0 ]; then
    rclone copy --transfers 8 "minio/$b" "ziel:$ziel"
  fi
  oben=$(rclone lsf -R --files-only "ziel:$ziel" | wc -l)
  echo "  $ziel: $n erwartet, $oben im Bucket"
  if [ "$oben" -ne "$n" ]; then
    echo "FEHLER: $ziel hat $oben Objekte statt $n." >&2
    exit 1
  fi
done < objekte.txt
rm -rf minio

echo "== 7. Image ${BILD}"
echo "  Bitte von Hand loeschen: Deploy, Container registry, umzug, Tag ${CI_PIPELINE_ID}."
echo "  Der Inhalt ist verschluesselt und ohne UMZUG_SCHLUESSEL nicht lesbar."

echo ""
echo "Import fertig. Weiter: swarm:deploy:prod in dieser Pipeline starten."
echo "docker02 bleibt aus; die Namen kommen mit der Umstellung des Wildcards."
