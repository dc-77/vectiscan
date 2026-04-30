#!/usr/bin/env bash
#
# VectiScan Cleanup Script — Q2/2026 Big-Bang Determinism Reset
# Spec: docs/deterministic/01-cleanup.md
#
# WIPES alle Scan-Daten, Reports, MinIO-Objekte, Caches.
# BEHAELT alle User-Accounts, Subscriptions, Schema, verified_domains.
#
# USAGE:
#   ./scripts/cleanup-prod.sh                        # Default: dry-run
#   ./scripts/cleanup-prod.sh --dry-run              # explizit dry-run
#   ./scripts/cleanup-prod.sh --confirm              # echter Wipe
#   ./scripts/cleanup-prod.sh --confirm --no-backup  # Backup ueberspringen
#   ./scripts/cleanup-prod.sh --confirm --skip-services # Service-Stop/Start skippen
#
# REQUIREMENTS:
#   - docker compose installiert
#   - .env mit POSTGRES_*, REDIS_*, MINIO_*-Vars
#   - Aktuelle Working Directory auf Repo-Root oder PROJECT_ROOT gesetzt
#
# EXIT CODES:
#   0  Success
#   1  User abort / pre-flight failed
#   2  Backup failed
#   3  DB cleanup failed
#   4  MinIO cleanup failed
#   5  Redis cleanup failed
#   6  Migration / Service-Restart failed
#   7  Smoke test failed

set -euo pipefail

# ------------------------------------------------------------------
# Konfiguration
# ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "${SCRIPT_DIR}/.." && pwd)}"
ENV_FILE="${ENV_FILE:-${PROJECT_ROOT}/.env}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
LOG_FILE="${PROJECT_ROOT}/cleanup-${TIMESTAMP}.log"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_ROOT}/backups}"

CONFIRMATION_STRING="${CONFIRMATION_STRING:-vectiscan-prod}"

# MinIO-Buckets (echte Namen aus api/src/lib/minio.ts):
MINIO_BUCKETS=(scan-rawdata scan-reports)
# Hinweis: scan-authorizations bleibt erhalten (Subscription-level Uploads).

# Compose-Services die gestoppt werden (postgres/redis/minio bleiben oben):
COMPOSE_SVC_STOP=(api scan-worker-1 scan-worker-2 precheck-worker-1 \
                  precheck-worker-2 report-worker frontend zap-1 zap-2)

# ------------------------------------------------------------------
# Argument-Parsing
# ------------------------------------------------------------------
DRY_RUN=true
DO_BACKUP=true
SKIP_SERVICES=false

for arg in "$@"; do
    case $arg in
        --confirm)       DRY_RUN=false ;;
        --dry-run)       DRY_RUN=true ;;
        --no-backup)     DO_BACKUP=false ;;
        --skip-services) SKIP_SERVICES=true ;;
        --help|-h)
            head -30 "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *)
            echo "Unknown argument: $arg" >&2
            echo "Use --help for usage" >&2
            exit 1
            ;;
    esac
done

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[0;33m'
    BLU='\033[0;34m'; BLD='\033[1m'; NC='\033[0m'
else
    RED=''; GRN=''; YLW=''; BLU=''; BLD=''; NC=''
fi

log()    { echo -e "${BLU}[INFO]${NC}  $*" | tee -a "$LOG_FILE"; }
warn()   { echo -e "${YLW}[WARN]${NC}  $*" | tee -a "$LOG_FILE"; }
err()    { echo -e "${RED}[ERR ]${NC}  $*" | tee -a "$LOG_FILE" >&2; }
ok()     { echo -e "${GRN}[ OK ]${NC}  $*" | tee -a "$LOG_FILE"; }
section(){ echo -e "\n${BLD}=== $* ===${NC}\n" | tee -a "$LOG_FILE"; }

run() {
    if $DRY_RUN; then
        echo -e "${YLW}[DRY ]${NC}  $*" | tee -a "$LOG_FILE"
    else
        echo -e "${BLU}[EXEC]${NC}  $*" | tee -a "$LOG_FILE"
        eval "$@"
    fi
}

# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------
mkdir -p "$(dirname "$LOG_FILE")"
section "VectiScan Cleanup — Q2/2026 Determinism Reset"
log "Project Root: $PROJECT_ROOT"
log "Env File:     $ENV_FILE"
log "Log File:     $LOG_FILE"
log "Mode:         $($DRY_RUN && echo 'DRY-RUN (kein Schaden)' || echo 'LIVE (loescht wirklich)')"
log "Backup:       $($DO_BACKUP && echo 'JA' || echo 'NEIN')"
log "Skip Services: $SKIP_SERVICES"

if [[ ! -f "$ENV_FILE" ]]; then
    err ".env file not found: $ENV_FILE"
    exit 1
fi

# .env zeilenweise parsen — KEIN `source`, weil bash sonst Werte mit
# Dollar-Zeichen (z.B. crypt-Hashes, Tokens mit $6$) als Variable-Refs
# expandiert und unter `set -u` mit "Variable nicht gesetzt" abbricht.
while IFS= read -r _line || [[ -n "$_line" ]]; do
    # Kommentare / Leerzeilen ueberspringen
    [[ -z "$_line" || "$_line" =~ ^[[:space:]]*# ]] && continue
    # Erstes "=" trennt key vom value
    _key="${_line%%=*}"
    _val="${_line#*=}"
    # Whitespace trimmen, optionale aussere Quotes entfernen
    _key="${_key#"${_key%%[![:space:]]*}"}"
    _key="${_key%"${_key##*[![:space:]]}"}"
    [[ -z "$_key" ]] && continue
    if [[ "$_val" =~ ^\".*\"$ ]]; then _val="${_val:1:-1}"; fi
    if [[ "$_val" =~ ^\'.*\'$ ]]; then _val="${_val:1:-1}"; fi
    export "$_key=$_val"
done < "$ENV_FILE"
unset _line _key _val

# DB-Variablen: prod-.env nutzt DB_* (siehe .gitlab-ci.yml deploy-base);
# Spec-Vorschlag verwendete POSTGRES_* — beide Namen werden akzeptiert.
DB_NAME="${POSTGRES_DB:-${DB_NAME:-vectiscan}}"
DB_USER="${POSTGRES_USER:-${DB_USER:-vectiscan}}"
DB_PASS="${POSTGRES_PASSWORD:-${DB_PASSWORD:-}}"
if [[ -z "$DB_PASS" ]]; then
    err "Weder POSTGRES_PASSWORD noch DB_PASSWORD in .env gesetzt"
    exit 1
fi

MINIO_ENDPOINT_URL="${MINIO_ENDPOINT_URL:-http://minio:9000}"
MINIO_AK="${MINIO_ACCESS_KEY:-}"
MINIO_SK="${MINIO_SECRET_KEY:-}"
if [[ -z "$MINIO_AK" || -z "$MINIO_SK" ]]; then
    err "MINIO_ACCESS_KEY / MINIO_SECRET_KEY fehlen in .env"
    exit 1
fi

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
psql_exec() {
    docker compose exec -T postgres \
        psql -U "$DB_USER" -d "$DB_NAME" -tAc "$1"
}

redis_exec() {
    docker compose exec -T redis redis-cli "$@"
}

mc_exec() {
    docker compose exec -T minio mc "$@"
}

# Setze MC-Alias falls noch nicht da.
ensure_mc_alias() {
    if ! mc_exec ls minio/ >/dev/null 2>&1; then
        log "Configuring mc alias 'minio'..."
        mc_exec alias set minio "$MINIO_ENDPOINT_URL" "$MINIO_AK" "$MINIO_SK" \
            >/dev/null 2>&1 || warn "mc alias setup failed (may need manual intervention)"
    fi
}

# ------------------------------------------------------------------
# Confirmation
# ------------------------------------------------------------------
if ! $DRY_RUN; then
    section "Confirmation Required"
    cat <<EOF
${RED}${BLD}WARNING:${NC} This will WIPE all scan data, reports, MinIO objects,
and threat-intel caches.

PRESERVED:
  - users, customers, verified_domains
  - Schema (alle Tabellen + Constraints)

DELETED:
  - orders (CASCADE: reports, scan_results, scan_targets-with-order,
    scan_run_targets, scan_target_hosts, finding_exclusions, order-level
    scan_authorizations)
  - subscriptions (CASCADE: subscription-level scan_targets,
    subscription-level scan_authorizations)
  - scan_schedules (komplett — Schedules haengen an Subscriptions)
  - audit_log (komplett)
  - MinIO-Buckets: ${MINIO_BUCKETS[*]}
  - Redis-Caches: nvd:* epss:* kev:* exploitdb:* ai_cache:* ws:*

Backup wird $($DO_BACKUP && echo 'ERSTELLT' || echo 'UEBERSPRUNGEN') in:
  $BACKUP_DIR

Zum Fortfahren tippe die Bestaetigung: ${BLD}${CONFIRMATION_STRING}${NC}
EOF
    # Bestaetigung kann ueber stdin (CI), via ENV oder interaktiv kommen.
    if [[ -n "${CONFIRM_STRING_INPUT:-}" ]]; then
        CONFIRM="$CONFIRM_STRING_INPUT"
    elif [[ ! -t 0 ]]; then
        # stdin ist eine Pipe (z.B. CI-Job): erste Zeile ist die Bestaetigung
        IFS= read -r CONFIRM || CONFIRM=""
    else
        read -r -p "> " CONFIRM
    fi
    if [[ "$CONFIRM" != "$CONFIRMATION_STRING" ]]; then
        err "Confirmation failed. Aborting."
        exit 1
    fi
    ok "Confirmed."
fi

# ==================================================================
# STEP 1: Pre-Flight
# ==================================================================
section "Step 1: Pre-Flight Checks"

if psql_exec "SELECT 1" >/dev/null 2>&1; then
    ok "PostgreSQL reachable"
else
    err "Cannot connect to PostgreSQL"
    exit 1
fi

if redis_exec PING >/dev/null 2>&1; then
    ok "Redis reachable"
else
    err "Cannot connect to Redis"
    exit 1
fi

ensure_mc_alias
if mc_exec ls minio/ >/dev/null 2>&1; then
    ok "MinIO reachable"
else
    err "Cannot reach MinIO"
    exit 1
fi

# Active-Scan-Check
ACTIVE=$(psql_exec "SELECT count(*) FROM orders WHERE status IN
    ('queued','scanning','passive_intel','dns_recon','scan_phase1',
     'scan_phase2','scan_phase3','report_generating','precheck_running',
     'pending_target_review')" 2>/dev/null || echo "ERROR")
if [[ "$ACTIVE" == "ERROR" ]]; then
    err "Active-scan check failed (DB query error)"
    exit 1
elif [[ "$ACTIVE" -gt 0 ]]; then
    err "$ACTIVE active scans/orders detected. Wait for completion or cancel them first."
    exit 1
fi
ok "No active scans (0)"

# ==================================================================
# STEP 2: Backup
# ==================================================================
if $DO_BACKUP; then
    section "Step 2: Backup"
    run "mkdir -p '$BACKUP_DIR'"
    BACKUP_FILE="$BACKUP_DIR/backup-pre-cleanup-${TIMESTAMP}.sql.gz"
    if $DRY_RUN; then
        run "docker compose exec -T postgres pg_dump -U $DB_USER $DB_NAME | gzip > $BACKUP_FILE"
    else
        log "Creating PostgreSQL dump..."
        if docker compose exec -T postgres pg_dump -U "$DB_USER" "$DB_NAME" \
                | gzip > "$BACKUP_FILE"; then
            BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
            ok "Backup written: $BACKUP_FILE ($BACKUP_SIZE)"
        else
            err "Backup failed"
            exit 2
        fi
    fi
else
    section "Step 2: Backup"
    warn "Backup SKIPPED (--no-backup)"
fi

# ==================================================================
# STEP 3: Stop Services
# ==================================================================
if $SKIP_SERVICES; then
    section "Step 3: Stop Services"
    warn "SKIPPED (--skip-services)"
else
    section "Step 3: Stop Services"
    log "Stopping: ${COMPOSE_SVC_STOP[*]}"
    run "docker compose stop ${COMPOSE_SVC_STOP[*]}"
    ok "Services stopped (postgres/redis/minio bleiben oben)"
fi

# ==================================================================
# STEP 4: DB Cleanup
# ==================================================================
section "Step 4: Database Cleanup"

# Strategie:
# 1. TRUNCATE audit_log (FK ohne ON DELETE → wuerde DELETE FROM orders blockieren)
# 2. DELETE FROM scan_schedules (Schedules haengen an subscriptions; vor
#    DELETE FROM subscriptions, falls FKs ohne CASCADE existieren)
# 3. DELETE FROM orders (CASCADE-DELETE handled reports, scan_results,
#    finding_exclusions, scan_targets-with-order, scan_target_hosts,
#    scan_run_targets, order-level scan_authorizations)
# 4. DELETE FROM subscriptions (CASCADE-DELETE handled subscription-level
#    scan_targets + scan_authorizations)
#
# Users, customers, verified_domains BLEIBEN — kein FK-Pfad.

CLEANUP_SQL="
BEGIN;
TRUNCATE TABLE audit_log RESTART IDENTITY;
DELETE FROM scan_schedules;
DELETE FROM orders;
DELETE FROM subscriptions;
COMMIT;
VACUUM ANALYZE;
"

if $DRY_RUN; then
    log "Would execute cleanup SQL:"
    echo "$CLEANUP_SQL" | sed 's/^/    /' | tee -a "$LOG_FILE"
else
    log "Executing cleanup SQL..."
    if echo "$CLEANUP_SQL" | docker compose exec -T postgres \
            psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 >/dev/null; then
        ok "DB cleanup committed"
    else
        err "DB cleanup failed"
        exit 3
    fi

    # Verifikation: erwartet 0 in Scan- + Subscription-Tabellen
    REMAINING=$(psql_exec "SELECT
        (SELECT count(*) FROM orders) +
        (SELECT count(*) FROM scan_results) +
        (SELECT count(*) FROM reports) +
        (SELECT count(*) FROM audit_log) +
        (SELECT count(*) FROM finding_exclusions) +
        (SELECT count(*) FROM subscriptions) +
        (SELECT count(*) FROM scan_targets) +
        (SELECT count(*) FROM scan_authorizations) +
        (SELECT count(*) FROM scan_schedules)")
    if [[ "$REMAINING" == "0" ]]; then
        ok "Verification: 0 rows in scan + subscription tables"
    else
        err "Verification FAILED: $REMAINING rows remaining"
        exit 3
    fi

    # Erhaltene Daten ausweisen
    USERS=$(psql_exec "SELECT count(*) FROM users")
    CUST=$(psql_exec "SELECT count(*) FROM customers")
    VDOM=$(psql_exec "SELECT count(*) FROM verified_domains")
    log "Preserved: $USERS users, $CUST customers, $VDOM verified_domains"
fi

# ==================================================================
# STEP 5: MinIO Cleanup
# ==================================================================
section "Step 5: MinIO Cleanup"

for BUCKET in "${MINIO_BUCKETS[@]}"; do
    if $DRY_RUN; then
        run "mc rm --recursive --force minio/$BUCKET/"
    else
        log "Clearing minio/$BUCKET/ ..."
        mc_exec rm --recursive --force "minio/$BUCKET/" 2>&1 \
            | tee -a "$LOG_FILE" \
            || warn "Bucket $BUCKET clear had errors (might be empty already)"
    fi
done

if ! $DRY_RUN; then
    for BUCKET in "${MINIO_BUCKETS[@]}"; do
        COUNT=$(mc_exec ls "minio/$BUCKET/" 2>/dev/null | wc -l)
        if [[ "$COUNT" == "0" ]]; then
            ok "minio/$BUCKET/ is empty"
        else
            warn "minio/$BUCKET/ still has $COUNT entries"
        fi
    done
fi

# ==================================================================
# STEP 6: Redis Cleanup
# ==================================================================
section "Step 6: Redis Cleanup"

for PATTERN in 'nvd:*' 'epss:*' 'kev:*' 'exploitdb:*' 'ai_cache:*' 'ws:*'; do
    if $DRY_RUN; then
        run "redis-cli --scan --pattern '$PATTERN' | xargs -r redis-cli DEL"
    else
        log "Deleting keys matching '$PATTERN'..."
        DELETED=$(docker compose exec -T redis sh -c \
            "redis-cli --scan --pattern '$PATTERN' | xargs -r -n100 redis-cli DEL | awk '{s+=\$1} END {print s+0}'" \
            2>&1 || echo "0")
        ok "$PATTERN: $DELETED keys deleted"
    fi
done

# BullMQ-Histories nur leeren, wenn Queues idle sind
if ! $DRY_RUN; then
    SCAN_QLEN=$(redis_exec LLEN "scan-pending" 2>/dev/null | tr -d '\r' || echo "0")
    REPORT_QLEN=$(redis_exec LLEN "report-pending" 2>/dev/null | tr -d '\r' || echo "0")
    PRECHECK_QLEN=$(redis_exec LLEN "precheck-pending" 2>/dev/null | tr -d '\r' || echo "0")
    if [[ "${SCAN_QLEN:-0}" == "0" && "${REPORT_QLEN:-0}" == "0" \
            && "${PRECHECK_QLEN:-0}" == "0" ]]; then
        log "BullMQ-Queues sind leer — bereinige Stale-State"
        redis_exec DEL scan-pending report-pending precheck-pending \
            >/dev/null 2>&1 || true
        ok "Queue-State entfernt"
    else
        warn "Queues sind nicht leer (scan=$SCAN_QLEN, report=$REPORT_QLEN, " \
             "precheck=$PRECHECK_QLEN) — Queues NICHT veraendert"
    fi
fi

# ==================================================================
# STEP 7: Restart Services + Migrations 016/017
# ==================================================================
section "Step 7: Restart Services (Migrations 016/017 laufen via api initDb)"

# Die Migrations 016/017 werden automatisch beim api-Start ausgefuehrt
# (api/src/lib/db.ts::initDb prueft information_schema und wendet
# fehlende Migrationen idempotent an).
if $SKIP_SERVICES; then
    warn "SKIPPED (--skip-services) — Migrations werden NICHT angewandt!"
    warn "Bitte manuell: docker compose up -d api"
else
    if $DRY_RUN; then
        run "docker compose up -d ${COMPOSE_SVC_STOP[*]}"
    else
        log "Starting services..."
        if docker compose up -d "${COMPOSE_SVC_STOP[@]}"; then
            ok "Services restarted"
        else
            err "Service restart failed"
            exit 6
        fi
    fi
fi

# ==================================================================
# STEP 8: Smoke-Test (Health-Endpoint)
# ==================================================================
section "Step 8: Smoke-Test"

if $DRY_RUN; then
    log "Would curl http://localhost:4000/health (or via Traefik)"
else
    # Warte bis API healthy ist (max 60s)
    log "Waiting for API to become healthy (max 60s)..."
    HEALTHY=false
    for _ in $(seq 1 12); do
        if docker compose exec -T api wget -q -O - http://localhost:4000/health \
                >/dev/null 2>&1; then
            HEALTHY=true
            break
        fi
        sleep 5
    done
    if $HEALTHY; then
        ok "API /health responds"
    else
        err "API health check failed after 60s"
        exit 7
    fi

    # Migration-Check (Spalten der 016 sollten existieren)
    POL_VER_EXISTS=$(psql_exec "SELECT EXISTS (SELECT 1 FROM information_schema.columns
        WHERE table_name='reports' AND column_name='policy_version')")
    TI_TBL_EXISTS=$(psql_exec "SELECT EXISTS (SELECT 1 FROM information_schema.tables
        WHERE table_name='threat_intel_snapshots')")
    if [[ "$POL_VER_EXISTS" == "t" && "$TI_TBL_EXISTS" == "t" ]]; then
        ok "Migrations 016 + 017 angewandt"
    else
        err "Migrations 016/017 fehlen (policy_version=$POL_VER_EXISTS, ti_table=$TI_TBL_EXISTS)"
        exit 7
    fi
fi

# ==================================================================
# Final Summary
# ==================================================================
section "Cleanup Summary"
log "Mode:         $($DRY_RUN && echo 'DRY-RUN (nichts wurde geaendert)' || echo 'LIVE')"
log "Log:          $LOG_FILE"
if $DO_BACKUP && ! $DRY_RUN; then
    log "Backup:       $BACKUP_FILE"
fi
ok "DONE"
