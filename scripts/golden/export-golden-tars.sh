#!/usr/bin/env bash
# S0c: Roh-Tars der Golden-Auftraege aus MinIO exportieren.
#
# Laeuft auf vectigal-docker02 im Deploy-Verzeichnis, ausgeloest vom manuellen
# GitLab-Job ops-export-golden-tars. Von aussen gibt es keinen Weg zu MinIO:
# der Dienst haengt ohne Port-Mapping und ohne Traefik-Router allein im Netz
# vectiscan-internal, und die API liefert keine Rohdaten.
#
# Gegenueber MinIO ist dieses Skript lesend: nur `mc stat` und `mc cp` aus dem
# Bucket heraus. Geschrieben wird ausschliesslich in /tmp des minio-Containers
# (danach aufgeraeumt) und in das Ausgabeverzeichnis des Jobs.
#
# Screenshots werden entfernt, bevor ein Tar das Verzeichnis verlaesst
# (spec/07 Abschnitt 1: Junkerwerk-Rohdaten duerfen ins Repo, Screenshots
# nicht). Das Neupacken ist deterministisch, zwei Laeufe liefern dieselbe Datei.
#
# Aufruf:
#   export-golden-tars.sh <orders.txt> <ausgabeverzeichnis> [deploy-verzeichnis]

set -euo pipefail

ORDERS_FILE="${1:?Pfad zu orders.txt fehlt}"
OUT_DIR="${2:?Ausgabeverzeichnis fehlt}"
DEPLOY_DIR="${3:-$PWD}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STRIPPER="$SCRIPT_DIR/strip-screenshots.py"
BUCKET="scan-rawdata"
ALIAS="golden"
CONTAINER_TMP="/tmp/golden-export"
MAX_BYTES=$((5 * 1024 * 1024))

log() { printf '[golden] %s\n' "$*"; }
err() { printf '[golden] FEHLER: %s\n' "$*" >&2; }

[[ -f "$ORDERS_FILE" ]] || { err "orders.txt nicht gefunden: $ORDERS_FILE"; exit 2; }
[[ -f "$STRIPPER" ]] || { err "strip-screenshots.py nicht gefunden: $STRIPPER"; exit 2; }

cd "$DEPLOY_DIR"
ENV_FILE="$DEPLOY_DIR/.env"
[[ -f "$ENV_FILE" ]] || { err ".env nicht gefunden: $ENV_FILE"; exit 2; }

# .env zeilenweise parsen, kein `source`: Werte mit Dollar-Zeichen wuerden sonst
# expandiert (gleiche Begruendung wie in scripts/cleanup-prod.sh).
while IFS= read -r _line || [[ -n "$_line" ]]; do
    [[ -z "$_line" || "$_line" =~ ^[[:space:]]*# ]] && continue
    _key="${_line%%=*}"
    _val="${_line#*=}"
    _key="${_key#"${_key%%[![:space:]]*}"}"
    _key="${_key%"${_key##*[![:space:]]}"}"
    [[ -z "$_key" ]] && continue
    if [[ "$_val" =~ ^\".*\"$ ]]; then _val="${_val:1:-1}"; fi
    if [[ "$_val" =~ ^\'.*\'$ ]]; then _val="${_val:1:-1}"; fi
    export "$_key=$_val"
done < "$ENV_FILE"
unset _line _key _val

MINIO_URL="${MINIO_ENDPOINT_URL:-http://minio:9000}"
: "${MINIO_ACCESS_KEY:?MINIO_ACCESS_KEY fehlt in .env}"
: "${MINIO_SECRET_KEY:?MINIO_SECRET_KEY fehlt in .env}"

# Alle docker-Aufrufe lesen stdin. Ohne </dev/null wuerde der erste Aufruf die
# restliche Auftragsliste aus der Schleife schlucken.
mc_exec() { docker compose exec -T minio mc "$@" </dev/null; }
minio_sh() { docker compose exec -T minio "$@" </dev/null; }

mkdir -p "$OUT_DIR"
REPORT="$OUT_DIR/export-report${GOLDEN_ORDER:+-$GOLDEN_ORDER}.txt"
: > "$REPORT"

log "MinIO-Alias setzen"
mc_exec alias set "$ALIAS" "$MINIO_URL" "$MINIO_ACCESS_KEY" "$MINIO_SECRET_KEY" >/dev/null

mc_exec rm --recursive --force "$CONTAINER_TMP" >/dev/null 2>&1 || true
minio_sh mkdir -p "$CONTAINER_TMP"

# Auftragsliste vorab einlesen, damit die Schleife nicht von stdin haengt.
# GOLDEN_ORDER schraenkt auf einen Auftrag ein. Der CI-Job nutzt das ueber
# parallel:matrix, weil der Artefakt-Upload dieser GitLab-Instanz schon bei
# wenigen hundert Kilobyte mit 413 abbricht; ein Auftrag je Job bleibt darunter.
if [[ -n "${GOLDEN_ORDER:-}" ]]; then
    ORDERS=("$GOLDEN_ORDER")
else
    mapfile -t ORDERS < "$ORDERS_FILE"
fi

ok=0
missing=0
oversize=0

for order in "${ORDERS[@]}"; do
    order="$(printf '%s' "$order" | tr -d '[:space:]')"
    [[ -z "$order" ]] && continue
    object="$ALIAS/$BUCKET/$order.tar.gz"

    if ! mc_exec stat "$object" >/dev/null 2>&1; then
        err "$order: Objekt fehlt in $BUCKET (vermutlich von cleanup-prod geraeumt)"
        printf '%s\tmissing\t-\t-\t-\t-\n' "$order" >> "$REPORT"
        missing=$((missing + 1))
        continue
    fi

    mc_exec cp --quiet "$object" "$CONTAINER_TMP/$order.tar.gz" >/dev/null
    raw="$OUT_DIR/$order.raw.tar.gz"
    docker compose cp "minio:$CONTAINER_TMP/$order.tar.gz" "$raw" >/dev/null </dev/null
    mc_exec rm --force "$CONTAINER_TMP/$order.tar.gz" >/dev/null 2>&1 || true

    before=$(stat -c %s "$raw")
    stripped="$OUT_DIR/$order.tar.gz"
    images=$(python3 "$STRIPPER" "$raw" "$stripped")
    after=$(stat -c %s "$stripped")
    rm -f "$raw"

    sum=$(sha256sum "$stripped" | cut -d' ' -f1)
    state="ok"
    if [[ "$after" -gt "$MAX_BYTES" ]]; then
        state="oversize"
        oversize=$((oversize + 1))
        err "$order: $after Bytes nach dem Strippen, Grenze $MAX_BYTES"
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$order" "$state" "$before" "$after" "$images" "$sum" >> "$REPORT"
    log "$order: $before -> $after Bytes, $images Bilder entfernt"
    ok=$((ok + 1))
done

minio_sh rm -rf "$CONTAINER_TMP" >/dev/null 2>&1 || true

log "Fertig: $ok exportiert, $missing fehlend, $oversize ueber der Groessengrenze"
log "Spalten in export-report.txt: order, status, bytes_vorher, bytes_nachher, bilder, sha256"
cat "$REPORT"

# Fehlende Objekte sind ein zu meldender Befund, kein Abbruch: die Mai-Laeufe
# koennen von cleanup-prod geraeumt sein.
exit 0
