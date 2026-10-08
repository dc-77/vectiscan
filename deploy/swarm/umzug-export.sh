#!/usr/bin/env bash
# =============================================================================
# Datenumzug VectiScan, Teil 1: Export auf docker02 (Job swarm:umzug:export)
# -----------------------------------------------------------------------------
# Laeuft auf dem Shell-Runner `vectigal` direkt auf docker02, im
# Compose-Projekt /opt/apps/vectiscan (wie deploy-auto).
#
# AB DEM ANHALTEN LAEUFT DAS UMZUGSFENSTER: frontend, api und alle Worker auf
# docker02 bleiben aus, Twenty laeuft weiter. Zurueck mit swarm:umzug:rueckweg.
#
# Transport als Image umzug:<Pipeline-ID> ueber registry-extern statt ueber
# den Datenknoten: docker02 erreicht docker-share01 nicht (5433 und 22 zu,
# gemessen am 08.10.2026). Alles ist mit UMZUG_SCHLUESSEL verschluesselt und
# traegt eine Pruefsumme des Klartexts. Die Paket-Registry ging nicht: der
# Proxy vor git-extern lehnte schon 7 MB mit HTTP 413 ab (protokoll-assist,
# 08.10.2026); die Registry nimmt Schichten stueckweise an.
#
# MinIO: Die Objekte kommen ueber die S3-Schnittstelle heraus, nicht als
# Rohdaten des Volumes (das Format auf der Platte ist MinIO-intern). mc laeuft
# als Wegwerf-Container aus dem lokal vorhandenen MinIO-Image, im Netz des
# Compose-Projekts und mit dem Arbeitsordner des Jobs eingehaengt. So braucht
# das Image weder Shell noch coreutils, nur die Datei mc. dl.min.io liefert
# den Client seit Oktober 2026 nicht mehr aus (410 Gone).
# =============================================================================
set -euo pipefail

APP_DIR=${DEPLOY_PATH:-/opt/apps/vectiscan}
REPO_DIR=${CI_PROJECT_DIR:?nur im CI-Job aufrufen}
ARBEIT="$REPO_DIR/umzug-arbeit"
BILD="${CI_REGISTRY_IMAGE}/umzug:${CI_PIPELINE_ID}"
BUCKETS="scan-rawdata scan-reports scan-authorizations scan-screenshots scan-debug"
APP_DIENSTE="frontend api scan-worker-1 scan-worker-2 scan-worker-3 precheck-worker-1 precheck-worker-2 report-worker"
AKTIV="'queued','scanning','passive_intel','dns_recon','scan_phase1','scan_phase2','scan_phase3','report_generating'"

: "${UMZUG_SCHLUESSEL:?CI-Variable UMZUG_SCHLUESSEL fehlt (Masked, Protected, Scope *)}"
if [ "${#UMZUG_SCHLUESSEL}" -lt 24 ]; then
  echo "FEHLER: UMZUG_SCHLUESSEL ist kuerzer als 24 Zeichen." >&2
  exit 1
fi
for t in docker openssl sha256sum tar find; do
  command -v "$t" >/dev/null || { echo "FEHLER: $t fehlt auf dem Runner." >&2; exit 1; }
done

cd "$APP_DIR"
dc() { docker compose "$@"; }
PGU=$(dc exec -T postgres printenv POSTGRES_USER | tr -d '\r')
PGD=$(dc exec -T postgres printenv POSTGRES_DB | tr -d '\r')
psql_q() { dc exec -T postgres psql -U "$PGU" -d "$PGD" -v ON_ERROR_STOP=1 -At "$@"; }

rm -rf "$ARBEIT"
mkdir -p "$ARBEIT/mc" "$ARBEIT/minio"
MINIO_C=$(dc ps -q minio)
MINIO_IMG=$(docker inspect -f '{{.Config.Image}}' "$MINIO_C")
NETZ=$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}' "$MINIO_C" | head -1)
envwert() { docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$MINIO_C" | sed -n "s/^$1=//p" | head -1; }
MU=$(envwert MINIO_ROOT_USER); MP=$(envwert MINIO_ROOT_PASSWORD)
# Ohne gesetzte Root-Werte startet MinIO mit seinen Vorgaben.
MU=${MU:-minioadmin}; MP=${MP:-minioadmin}
mcx() {
  docker run --rm --network "$NETZ" --user "$(id -u):$(id -g)" -v "$ARBEIT:/arbeit" \
    --entrypoint mc "$MINIO_IMG" -C /arbeit/mc "$@"
}

gestoppt=nein
abbruch() {
  rm -rf "$ARBEIT/mc"
  if [ "$gestoppt" = ja ]; then
    echo "" >&2
    echo "ABBRUCH nach dem Anhalten. Die Anwendung auf docker02 ist AUS." >&2
    echo "Zurueck: Job swarm:umzug:rueckweg in dieser Pipeline starten." >&2
  fi
}
trap abbruch EXIT

echo "== 1. Vorpruefung (noch nichts angehalten)"
dc ps --format '{{.Service}} {{.State}}' | sort | tr '\n' ' '; echo
aktiv=$(psql_q -c "SELECT count(*) FROM orders WHERE status IN (${AKTIV})")
echo "  aktive Auftraege: $aktiv"
if [ "$aktiv" -gt 0 ] && [ "${UMZUG_TROTZDEM:-nein}" != "ja" ]; then
  echo "FEHLER: Es laufen noch Auftraege. Spaeter wiederholen oder UMZUG_TROTZDEM=ja setzen." >&2
  exit 1
fi
echo "  MinIO-Image $MINIO_IMG, Netz $NETZ"
mcx --version | head -1
mcx alias set q http://minio:9000 "$MU" "$MP" >/dev/null
mcx ls q/ | sed 's/^/    /'

echo "== 2. Anwendung auf docker02 anhalten (Twenty laeuft weiter)"
# shellcheck disable=SC2086
dc stop $APP_DIENSTE
gestoppt=ja

echo "== 3. Datenbank sichern (pg_dump, reines SQL)"
dc exec -T postgres pg_dump -U "$PGU" -d "$PGD" --no-owner --no-privileges > "$ARBEIT/db.sql"
psql_q < "$REPO_DIR/deploy/swarm/umzug-zaehlen.sql" > "$ARBEIT/zaehlung.txt"
echo "  $(wc -c < "$ARBEIT/db.sql") Bytes SQL, $(wc -l < "$ARBEIT/zaehlung.txt") Tabellen"
grep -E '^public\.(orders|reports|users|customers)\|' "$ARBEIT/zaehlung.txt" | sed 's/^/    /' || true

echo "== 4. MinIO-Objekte ueber S3 herausholen"
: > "$ARBEIT/objekte.txt"
for b in $BUCKETS; do
  if mcx ls "q/$b" >/dev/null 2>&1; then
    mcx mirror --quiet "q/$b" "/arbeit/minio/$b" >/dev/null
    n=$(mcx ls --recursive "q/$b" | wc -l)
  else
    n=0
  fi
  mkdir -p "$ARBEIT/minio/$b"
  lokal=$(find "$ARBEIT/minio/$b" -type f | wc -l)
  echo "  $b: $n Objekte, $lokal Dateien"
  if [ "$lokal" -ne "$n" ]; then
    echo "FEHLER: $b hat $n Objekte, aber $lokal Dateien kamen heraus." >&2
    exit 1
  fi
  echo "$b|$n" >> "$ARBEIT/objekte.txt"
done
rm -rf "$ARBEIT/mc"

echo "== 5. Verschluesseln und als Image ${BILD} in die Registry"
cd "$ARBEIT"
tar -cf minio.tar -C minio .
rm -rf minio
sha256sum db.sql minio.tar > pruefsummen.txt
for f in db.sql minio.tar; do
  openssl enc -aes-256-cbc -pbkdf2 -iter 200000 -salt -pass env:UMZUG_SCHLUESSEL -in "$f" -out "$f.enc"
done
rm -f db.sql minio.tar
mkdir bild
mv db.sql.enc minio.tar.enc zaehlung.txt objekte.txt pruefsummen.txt bild/
ls -l bild | sed 's/^/  /'
printf 'FROM scratch\nCOPY . /umzug/\n' > bild/Dockerfile
echo "${CI_REGISTRY_PASSWORD}" | docker login "${CI_REGISTRY}" -u "${CI_REGISTRY_USER}" --password-stdin >/dev/null
# Ohne Attestierungen: registry-extern kennt deren Medientyp nicht. Nur die
# Umgebungsvariable, kein --provenance: der Shell-Runner baut sonst ohne
# buildx, und der alte Builder kennt den Schalter nicht.
BUILDX_NO_DEFAULT_ATTESTATIONS=1 docker build -q -t "$BILD" bild
docker push -q "$BILD"
docker rmi "$BILD" >/dev/null
docker logout "${CI_REGISTRY}" >/dev/null
rm -rf bild

trap - EXIT
echo ""
echo "Export fertig. Die Anwendung auf docker02 bleibt AUS, Twenty laeuft."
echo "Weiter: Job swarm:umzug:import in dieser Pipeline (Image ${BILD})."
