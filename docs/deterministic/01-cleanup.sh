#!/usr/bin/env bash
#
# VectiScan Cleanup Script — Q2/2026 Big-Bang Determinism Reset
#
# WIPES alle Scan-Daten, Reports, MinIO-Objekte, Caches.
# BEHÄLT alle User-Accounts, Subscriptions, Schema, verified_domains.
#
# USAGE:
#   ./01-cleanup.sh                    # Default: --dry-run
#   ./01-cleanup.sh --dry-run          # Zeigt was passieren würde, ändert nichts
#   ./01-cleanup.sh --confirm          # Echter Wipe mit Confirmation-Prompt
#   ./01-cleanup.sh --confirm --no-backup    # Skip Backup-Schritt
#   ./01-cleanup.sh --confirm --skip-services # Service-Stop/Start überspringen
#                                              (z.B. wenn manuell schon gestoppt)
#
# REQUIREMENTS:
#   - docker compose (for service control)
#   - psql client (or via docker exec)
#   - mc (MinIO client) or via docker exec into minio container
#   - redis-cli or via docker exec
#   - .env mit DB_*, REDIS_*, MINIO_*-Vars
#
# EXIT CODES:
#   0  Success
#   1  User abort or pre-flight failed
#   2  Backup failed
#   3  DB cleanup failed
#   4  MinIO cleanup failed
#   5  Redis cleanup failed
#   6  Migration failed
#   7  Smoke test failed

set -euo pipefail

# ------------------------------------------------------------------
# Konfiguration
# ------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd "${SCRIPT_DIR}/../../.." && pwd)}"
ENV_FILE="${ENV_FILE:-${PROJECT_ROOT}/.env}"
LOG_FILE="${PROJECT_ROOT}/cleanup-$(date +%Y%m%d-%H%M%S).log"
BACKUP_DIR="${BACKUP_DIR:-${PROJECT_ROOT}/backups}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

# Confirmation-String den User eintippen muss
CONFIRMATION_STRING="${CONFIRMATION_STRING:-vectiscan-prod}"

# ------------------------------------------------------------------
# Argument-Parsing
# ------------------------------------------------------------------
DRY_RUN=true
DO_BACKUP=true
SKIP_SERVICES=false

for arg in "$@"; do
    case $arg in
        --confirm)      DRY_RUN=false ;;
        --dry-run)      DRY_RUN=true ;;
        --no-backup)    DO_BACKUP=false ;;
        --skip-services) SKIP_SERVICES=true ;;
        --help|-h)
            head -40 "$0"
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
# Farben + Logging
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

# Wrap für DRY_RUN-Modus: zeigt Befehl, führt nur aus wenn nicht dry-run
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
section "VectiScan Cleanup — Q2/2026 Determinism Reset"
log "Project Root: $PROJECT_ROOT"
log "Env File:     $ENV_FILE"
log "Log File:     $LOG_FILE"
log "Mode:         $($DRY_RUN && echo 'DRY-RUN (kein Schaden)' || echo 'LIVE (wird wirklich löschen!)')"
log "Backup:       $($DO_BACKUP && echo 'JA' || echo 'NEIN')"
log "Skip Svcs:    $SKIP_SERVICES"

if [[ ! -f "$ENV_FILE" ]]; then
    err "Env file not found: $ENV_FILE"
    exit 1
fi

# Lade ENV
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

# Defaults für DB/Redis/MinIO falls in .env nicht gesetzt
DB_HOST="${POSTGRES_HOST:-postgres}"
DB_PORT="${POSTGRES_PORT:-5432}"
DB_NAME="${POSTGRES_DB:-vectiscan}"
DB_USER="${POSTGRES_USER:-vectiscan}"
DB_PASS="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD missing in .env}"

REDIS_HOST="${REDIS_HOST:-redis}"
REDIS_PORT="${REDIS_PORT:-6379}"

MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://minio:9000}"
MINIO_ACCESS_KEY="${MINIO_ACCESS_KEY:?MINIO_ACCESS_KEY missing in .env}"
MINIO_SECRET_KEY="${MINIO_SECRET_KEY:?MINIO_SECRET_KEY missing in .env}"

# Hilfs-Wrapper für DB/Redis/MinIO via docker exec
psql_exec() {
    docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" -tAc "$1"
}
psql_run_file() {
    docker compose exec -T postgres psql -U "$DB_USER" -d "$DB_NAME" < "$1"
}
redis_exec() {
    docker compose exec -T redis redis-cli "$@"
}
mc_exec() {
    docker compose exec -T minio mc "$@"
}

# ------------------------------------------------------------------
# Confirmation-Prompt (nur in LIVE-Modus)
# ------------------------------------------------------------------
if ! $DRY_RUN; then
    section "Confirmation Required"
    cat <<EOF
${RED}${BLD}WARNING:${NC} This will WIPE all scan data, reports, MinIO objects,
and threat-intel caches.

The following will be PRESERVED:
  - User accounts
  - Subscriptions + subscription_domains
  - verified_domains
  - Schema (tables, indexes, constraints)

The following will be DELETED:
  - All orders, scan_results, reports, findings, audit_log
  - All MinIO objects in scan-rawdata/, scan-debug/, reports/
  - All Redis caches (NVD, EPSS, KEV, ExploitDB, AI-Cache)

Backup will be ${DO_BACKUP:+CREATED}${DO_BACKUP:-SKIPPED} in:
  $BACKUP_DIR

To proceed, type the confirmation string: ${BLD}${CONFIRMATION_STRING}${NC}
EOF
    read -r -p "> " CONFIRM
    if [[ "$CONFIRM" != "$CONFIRMATION_STRING" ]]; then
        err "Confirmation failed. Aborting."
        exit 1
    fi
    ok "Confirmed."
fi

# ==================================================================
# STEP 1: Pre-Flight Checks
# ==================================================================
section "Step 1: Pre-Flight Checks"

# DB-Connectivity
if psql_exec "SELECT 1" >/dev/null 2>&1; then
    ok "PostgreSQL reachable"
else
    err "Cannot connect to PostgreSQL"
    exit 1
fi

# Redis-Connectivity
if redis_exec PING >/dev/null 2>&1; then
    ok "Redis reachable"
else
    err "Cannot connect to Redis"
    exit 1
fi

# MinIO-Connectivity (mc alias check)
# TODO(claude-code): mc alias setup ggf. nachziehen wenn nicht vorkonfiguriert
if mc_exec ls minio/ >/dev/null 2>&1; then
    ok "MinIO reachable"
else
    warn "MinIO mc alias 'minio' not configured — attempting setup"
    run "mc_exec alias set minio '$MINIO_ENDPOINT' '$MINIO_ACCESS_KEY' '$MINIO_SECRET_KEY'"
fi

# Active-Scan-Check
ACTIVE=$(psql_exec "SELECT count(*) FROM orders WHERE status IN
    ('queued','scanning','passive_intel','dns_recon','scan_phase1',
     'scan_phase2','scan_phase3','report_generating')" || echo "ERROR")
if [[ "$ACTIVE" == "ERROR" ]]; then
    err "Active-scan check failed"
    exit 1
elif [[ "$ACTIVE" -gt 0 ]]; then
    err "$ACTIVE active scans detected. Wait for completion or cancel them first."
    exit 1
else
    ok "No active scans (0)"
fi

# ==================================================================
# STEP 2: Backup
# ==================================================================
if $DO_BACKUP; then
    section "Step 2: Backup"
    run "mkdir -p '$BACKUP_DIR'"
    BACKUP_FILE="$BACKUP_DIR/backup-pre-cleanup-${TIMESTAMP}.sql.gz"
    if $DRY_RUN; then
        run "pg_dump > $BACKUP_FILE.gz"
    else
        log "Creating PostgreSQL dump..."
        if docker compose exec -T postgres pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$BACKUP_FILE"; then
            BACKUP_SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
            ok "Backup written: $BACKUP_FILE ($BACKUP_SIZE)"
        else
            err "Backup failed"
            exit 2
        fi
    fi
else
    section "Step 2: Backup"
    warn "Backup SKIPPED (--no-backup specified)"
fi

# ==================================================================
# STEP 3: Stop Services (außer postgres/redis/minio)
# ==================================================================
if $SKIP_SERVICES; then
    section "Step 3: Stop Services"
    warn "SKIPPED (--skip-services specified)"
else
    section "Step 3: Stop Services"
    log "Stopping api, scan-worker-1, scan-worker-2, report-worker, frontend..."
    run "docker compose stop api scan-worker-1 scan-worker-2 report-worker frontend zap-1 zap-2"
    ok "Services stopped (DB/Redis/MinIO bleiben oben)"
fi

# ==================================================================
# STEP 4: DB Cleanup
# ==================================================================
section "Step 4: Database Cleanup"

if $DRY_RUN; then
    log "Would TRUNCATE: orders, scan_results, report_findings_data,"
    log "                 report_findings_exclusions, reports, report_versions,"
    log "                 audit_log RESTART IDENTITY CASCADE"
    log "Would DELETE FROM scan_schedules WHERE last_run_at IS NOT NULL"
    log "Would VACUUM ANALYZE"
else
    log "Truncating scan-related tables (CASCADE)..."
    psql_exec "BEGIN;
        TRUNCATE TABLE
            orders,
            scan_results,
            report_findings_data,
            report_findings_exclusions,
            reports,
            report_versions,
            audit_log
        RESTART IDENTITY CASCADE;
        DELETE FROM scan_schedules WHERE last_run_at IS NOT NULL;
        COMMIT;" || { err "DB cleanup failed"; exit 3; }
    ok "Tables truncated"

    log "VACUUM ANALYZE (reclaim disk space)..."
    psql_exec "VACUUM ANALYZE" || warn "VACUUM ANALYZE failed (non-fatal)"
    ok "VACUUM done"

    # Verifikation
    REMAINING=$(psql_exec "SELECT
        (SELECT count(*) FROM orders) +
        (SELECT count(*) FROM scan_results) +
        (SELECT count(*) FROM report_findings_data) +
        (SELECT count(*) FROM reports) +
        (SELECT count(*) FROM audit_log)")
    if [[ "$REMAINING" == "0" ]]; then
        ok "Verification: 0 rows in scan tables"
    else
        err "Verification FAILED: $REMAINING rows remaining"
        exit 3
    fi

    # User/Subscriptions sollten erhalten sein
    USERS=$(psql_exec "SELECT count(*) FROM users")
    SUBS=$(psql_exec "SELECT count(*) FROM subscriptions")
    log "Preserved: $USERS users, $SUBS subscriptions"
fi

# ==================================================================
# STEP 5: MinIO Cleanup
# ==================================================================
section "Step 5: MinIO Cleanup"

for BUCKET in scan-rawdata scan-debug reports; do
    if $DRY_RUN; then
        run "mc rm --recursive --force minio/$BUCKET/"
    else
        log "Clearing minio/$BUCKET/ ..."
        mc_exec rm --recursive --force "minio/$BUCKET/" 2>&1 | tee -a "$LOG_FILE" || \
            warn "Bucket $BUCKET clear had errors (might be empty already)"
    fi
done

# Verifikation
if ! $DRY_RUN; then
    for BUCKET in scan-rawdata scan-debug reports; do
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

# TODO(claude-code): Falls eure Redis-DB-Nummer != 0 ist, hier explizit -n N
for PATTERN in 'nvd:*' 'epss:*' 'kev:*' 'exploitdb:*' 'ai_cache:*' 'ws:*'; do
    if $DRY_RUN; then
        run "redis-cli --scan --pattern '$PATTERN' | xargs -r redis-cli DEL"
    else
        log "Deleting keys matching '$PATTERN'..."
        # Workaround: Pipe through xargs in einem einzelnen exec-Aufruf
        DELETED=$(docker compose exec -T redis sh -c \
            "redis-cli --scan --pattern '$PATTERN' | xargs -r redis-cli DEL | tail -1" \
            2>&1 | tail -1 || echo "0")
        ok "$PATTERN: $DELETED keys deleted"
    fi
done

# BullMQ: nur wenn alle Queues idle
if ! $DRY_RUN; then
    QUEUE_LEN=$(redis_exec LLEN bull:scan-pending:waiting 2>/dev/null || echo "0")
    if [[ "$QUEUE_LEN" == "0" ]]; then
        log "BullMQ scan-pending queue empty — clearing stale data"
        redis_exec DEL "bull:scan-pending:completed" "bull:scan-pending:failed" \
                       "bull:report-pending:completed" "bull:report-pending:failed" \
            >/dev/null 2>&1 || true
        ok "BullMQ histories cleared"
    else
        warn "BullMQ scan-pending has $QUEUE_LEN waiting jobs — leaving alone"
    fi
fi

# ==================================================================
# STEP 7: Migrations
# ==================================================================
section "Step 7: Apply Migrations 014 + 015"

# TODO(claude-code): Anpassen an euren Migrations-Runner
# Optionen:
#   a) Node-basiert: npm run migrate (in api/)
#   b) Direkt psql_run_file für jede SQL-Datei
#   c) Eigenes db.ts::runMigrations()
#
# Hier Variante (b) als sicherster Weg:

MIGRATION_DIR="${PROJECT_ROOT}/api/src/migrations"
for MIG in "${MIGRATION_DIR}/014_severity_policy.sql" \
           "${MIGRATION_DIR}/015_threat_intel_snapshots.sql"; do
    if [[ ! -f "$MIG" ]]; then
        err "Migration not found: $MIG"
        err "Did you copy 05-014-* and 05-015-*.sql into $MIGRATION_DIR?"
        exit 6
    fi
    if $DRY_RUN; then
        log "Would apply migration: $(basename "$MIG")"
    else
        log "Applying $(basename "$MIG")..."
        psql_run_file "$MIG" || { err "Migration $(basename "$MIG") failed"; exit 6; }
        ok "Applied $(basename "$MIG")"
    fi
done

# ==================================================================
# STEP 8: Restart Services
# ==================================================================
if $SKIP_SERVICES; then
    section "Step 8: Restart Services"
    warn "SKIPPED (--skip-services specified)"
else
    section "Step 8: Restart Services"
    run "docker compose up -d api scan-worker-1 scan-worker-2 report-worker frontend zap-1 zap-2"
    ok "Services started"
fi

# ==================================================================
# STEP 9: Smoke Test
# ==================================================================
section "Step 9: Smoke Test"

if $DRY_RUN; then
    log "Would: GET /health"
    log "Would: psql SELECT count(*) FROM users (sollte > 0 sein)"
    log "Would: mc ls minio/scan-rawdata/ (sollte leer sein)"
else
    sleep 5  # Warm-up
    if curl -sf "http://localhost:${API_PORT:-3001}/health" >/dev/null 2>&1; then
        ok "API health check passed"
    else
        warn "API health check failed (might still be warming up)"
    fi

    USERS=$(psql_exec "SELECT count(*) FROM users")
    if [[ "$USERS" -gt 0 ]]; then
        ok "Users preserved: $USERS"
    else
        err "Users count is 0 — something went wrong!"
        exit 7
    fi
fi

# ==================================================================
# DONE
# ==================================================================
section "DONE"
if $DRY_RUN; then
    cat <<EOF
${YLW}This was a DRY-RUN. Nothing was actually changed.${NC}

To execute the cleanup for real:
  $0 --confirm

Log file: $LOG_FILE
EOF
else
    cat <<EOF
${GRN}Cleanup completed successfully.${NC}

Next steps:
  1. Run a smoke-scan against a test domain (siehe 99-CUTOVER.md, Smoke-Test #2)
  2. Verify findings have severity_provenance set (Migration 014 active)
  3. Verify AI cache is starting fresh
  4. Monitor logs for first scan: docker compose logs -f scan-worker-1

Backup: ${DO_BACKUP:+$BACKUP_FILE}${DO_BACKUP:-(skipped)}
Log:    $LOG_FILE
EOF
fi

exit 0
