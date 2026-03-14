#!/usr/bin/env bash
# VectiScan E2E Package Tests
# Usage: ./e2e_package_tests.sh [--api-url URL]
#
# Prerequisites:
#   - curl, jq installed
#   - VectiScan API accessible
#   - Network access to scanme.nmap.org
set -euo pipefail

# ── Colors ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Defaults ──────────────────────────────────────────────────────────
API_URL="https://scan-api.vectigal.tech"
DOMAIN="scanme.nmap.org"
POLL_INTERVAL=30        # seconds between status polls
SCAN_TIMEOUT=3600       # 60 minutes max per scan
PACKAGES=("basic" "professional" "nis2")

# ── Parse arguments ──────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --api-url)
            API_URL="$2"
            shift 2
            ;;
        --api-url=*)
            API_URL="${1#*=}"
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--api-url URL]"
            echo "  --api-url  VectiScan API base URL (default: https://scan-api.vectigal.tech)"
            exit 0
            ;;
        *)
            echo -e "${RED}Unknown argument: $1${NC}"
            exit 1
            ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────
pass() { echo -e "  ${GREEN}✔ PASS${NC} $1"; }
fail() { echo -e "  ${RED}✘ FAIL${NC} $1"; FAILURES=$((FAILURES + 1)); }
info() { echo -e "  ${CYAN}ℹ${NC} $1"; }
header() { echo -e "\n${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"; echo -e "${BOLD}${BLUE}  $1${NC}"; echo -e "${BOLD}${BLUE}═══════════════════════════════════════════════════════${NC}"; }
section() { echo -e "\n${YELLOW}── $1 ──${NC}"; }

FAILURES=0
TOTAL_CHECKS=0
declare -A SCAN_IDS
declare -A PDF_FILES
declare -A PDF_SIZES

cleanup() {
    for pkg in "${PACKAGES[@]}"; do
        local pdf="${PDF_FILES[$pkg]:-}"
        if [[ -n "$pdf" && -f "$pdf" ]]; then
            rm -f "$pdf"
        fi
    done
}
trap cleanup EXIT

# ── Prerequisite checks ──────────────────────────────────────────────
header "VectiScan E2E Package Tests"
echo -e "  API URL:  ${CYAN}${API_URL}${NC}"
echo -e "  Domain:   ${CYAN}${DOMAIN}${NC}"
echo -e "  Packages: ${CYAN}${PACKAGES[*]}${NC}"
echo ""

for cmd in curl jq; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${RED}Error: $cmd is not installed.${NC}"
        exit 1
    fi
done

section "Health Check"
HEALTH_RESP=$(curl -sk -o /dev/null -w "%{http_code}" "${API_URL}/health" 2>/dev/null || true)
if [[ "$HEALTH_RESP" == "200" ]]; then
    pass "API health endpoint reachable (HTTP 200)"
else
    fail "API health endpoint returned HTTP ${HEALTH_RESP}"
    echo -e "${RED}Cannot continue without a healthy API.${NC}"
    exit 1
fi

# ── Start scans ──────────────────────────────────────────────────────
for pkg in "${PACKAGES[@]}"; do
    header "Package: ${pkg^^}"

    section "Starting scan"
    START_RESP=$(curl -sk -X POST "${API_URL}/api/scans" \
        -H "Content-Type: application/json" \
        -d "{\"domain\": \"${DOMAIN}\", \"package\": \"${pkg}\"}" 2>/dev/null)

    SUCCESS=$(echo "$START_RESP" | jq -r '.success // false')
    if [[ "$SUCCESS" != "true" ]]; then
        ERROR=$(echo "$START_RESP" | jq -r '.error // "unknown error"')
        fail "Failed to start ${pkg} scan: ${ERROR}"
        continue
    fi

    SCAN_ID=$(echo "$START_RESP" | jq -r '.data.id // .data.scanId // empty')
    if [[ -z "$SCAN_ID" ]]; then
        fail "No scan ID returned for ${pkg}"
        continue
    fi

    SCAN_IDS[$pkg]="$SCAN_ID"
    pass "Scan started (ID: ${SCAN_ID})"

    # ── Poll for completion ──────────────────────────────────────────
    section "Polling for completion (timeout: ${SCAN_TIMEOUT}s)"
    ELAPSED=0
    FINAL_STATUS=""

    while [[ $ELAPSED -lt $SCAN_TIMEOUT ]]; do
        STATUS_RESP=$(curl -sk "${API_URL}/api/scans/${SCAN_ID}" 2>/dev/null)
        STATUS=$(echo "$STATUS_RESP" | jq -r '.data.status // "unknown"')

        if [[ "$STATUS" == "report_complete" ]]; then
            FINAL_STATUS="report_complete"
            info "Scan completed after ${ELAPSED}s"
            break
        elif [[ "$STATUS" == "failed" ]]; then
            FINAL_STATUS="failed"
            fail "Scan failed after ${ELAPSED}s"
            break
        fi

        printf "  ${CYAN}⏳${NC} Status: %-20s (${ELAPSED}s elapsed)\r" "$STATUS"
        sleep "$POLL_INTERVAL"
        ELAPSED=$((ELAPSED + POLL_INTERVAL))
    done

    echo "" # clear the \r line

    if [[ -z "$FINAL_STATUS" ]]; then
        fail "Scan timed out after ${SCAN_TIMEOUT}s"
        continue
    fi

    if [[ "$FINAL_STATUS" == "failed" ]]; then
        continue
    fi

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    pass "Scan completed successfully"

    # ── Verify package field ─────────────────────────────────────────
    section "Verifying response fields"
    RESP_PKG=$(echo "$STATUS_RESP" | jq -r '.data.package // "missing"')
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ "$RESP_PKG" == "$pkg" ]]; then
        pass "Package field matches: ${RESP_PKG}"
    else
        fail "Package field mismatch: expected '${pkg}', got '${RESP_PKG}'"
    fi

    # ── Package-specific scan result checks ──────────────────────────
    section "Package-specific checks (${pkg})"

    case "$pkg" in
        basic)
            # Check: no nikto/nuclei in scan results
            SCAN_RESULTS=$(echo "$STATUS_RESP" | jq -r '.data.scan_results // .data.scanResults // empty' 2>/dev/null)
            HAS_NIKTO=$(echo "$STATUS_RESP" | jq -r '.. | .tool? // empty' 2>/dev/null | grep -ci "nikto" || true)
            HAS_NUCLEI=$(echo "$STATUS_RESP" | jq -r '.. | .tool? // empty' 2>/dev/null | grep -ci "nuclei" || true)

            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [[ "$HAS_NIKTO" -eq 0 ]]; then
                pass "No nikto results in basic scan"
            else
                fail "Basic scan should not include nikto results"
            fi

            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [[ "$HAS_NUCLEI" -eq 0 ]]; then
                pass "No nuclei results in basic scan"
            else
                fail "Basic scan should not include nuclei results"
            fi

            # Check: max 3 hosts
            HOST_COUNT=$(echo "$STATUS_RESP" | jq -r '.data.hosts // [] | length' 2>/dev/null || echo "0")
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [[ "$HOST_COUNT" -le 3 ]]; then
                pass "Host count within limit: ${HOST_COUNT} <= 3"
            else
                fail "Host count exceeds limit: ${HOST_COUNT} > 3"
            fi
            ;;

        professional)
            # Check: all tools present
            for tool in nmap webtech wafw00f testssl nikto nuclei gobuster gowitness; do
                HAS_TOOL=$(echo "$STATUS_RESP" | jq -r '.. | .tool? // empty' 2>/dev/null | grep -ci "$tool" || true)
                TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
                if [[ "$HAS_TOOL" -gt 0 ]]; then
                    pass "Tool present: ${tool}"
                else
                    fail "Tool missing: ${tool}"
                fi
            done
            ;;

        nis2)
            # Same tools as professional
            for tool in nmap webtech wafw00f testssl nikto nuclei gobuster gowitness; do
                HAS_TOOL=$(echo "$STATUS_RESP" | jq -r '.. | .tool? // empty' 2>/dev/null | grep -ci "$tool" || true)
                TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
                if [[ "$HAS_TOOL" -gt 0 ]]; then
                    pass "Tool present: ${tool}"
                else
                    fail "Tool missing: ${tool}"
                fi
            done
            ;;
    esac

    # ── Download PDF ─────────────────────────────────────────────────
    section "Downloading PDF report"
    REPORT_RESP=$(curl -sk "${API_URL}/api/scans/${SCAN_ID}/report" 2>/dev/null)
    DOWNLOAD_URL=$(echo "$REPORT_RESP" | jq -r '.data.url // .data.downloadUrl // empty' 2>/dev/null)

    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ -z "$DOWNLOAD_URL" ]]; then
        fail "No download URL returned for ${pkg} report"
        continue
    fi
    pass "Download URL received"

    PDF_FILE=$(mktemp "/tmp/vectiscan-${pkg}-XXXXXX.pdf")
    PDF_FILES[$pkg]="$PDF_FILE"

    HTTP_CODE=$(curl -sk -o "$PDF_FILE" -w "%{http_code}" "$DOWNLOAD_URL" 2>/dev/null)
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ "$HTTP_CODE" == "200" ]]; then
        pass "PDF downloaded (HTTP 200)"
    else
        fail "PDF download failed (HTTP ${HTTP_CODE})"
        continue
    fi

    FILE_SIZE=$(stat -c%s "$PDF_FILE" 2>/dev/null || stat -f%z "$PDF_FILE" 2>/dev/null || echo "0")
    PDF_SIZES[$pkg]=$FILE_SIZE
    info "PDF size: ${FILE_SIZE} bytes ($(( FILE_SIZE / 1024 )) KB)"

    # ── PDF size expectations ────────────────────────────────────────
    section "PDF size validation"
    case "$pkg" in
        basic)
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [[ $FILE_SIZE -lt 512000 ]]; then
                pass "Basic PDF under 500 KB (${FILE_SIZE} bytes)"
            else
                fail "Basic PDF exceeds 500 KB (${FILE_SIZE} bytes)"
            fi
            ;;
        professional)
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [[ $FILE_SIZE -ge 204800 && $FILE_SIZE -le 2097152 ]]; then
                pass "Professional PDF between 200 KB and 2 MB (${FILE_SIZE} bytes)"
            else
                fail "Professional PDF outside expected range 200KB-2MB (${FILE_SIZE} bytes)"
            fi
            ;;
        nis2)
            TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
            if [[ $FILE_SIZE -ge 204800 ]]; then
                pass "NIS2 PDF at least 200 KB (${FILE_SIZE} bytes)"
            else
                fail "NIS2 PDF unexpectedly small (${FILE_SIZE} bytes)"
            fi
            ;;
    esac
done

# ── Cross-package PDF size comparison ────────────────────────────────
header "Cross-Package Comparison"

section "PDF size ordering"
BASIC_SIZE=${PDF_SIZES[basic]:-0}
PRO_SIZE=${PDF_SIZES[professional]:-0}
NIS2_SIZE=${PDF_SIZES[nis2]:-0}

info "Basic:        $(( BASIC_SIZE / 1024 )) KB"
info "Professional: $(( PRO_SIZE / 1024 )) KB"
info "NIS2:         $(( NIS2_SIZE / 1024 )) KB"

if [[ $BASIC_SIZE -gt 0 && $PRO_SIZE -gt 0 ]]; then
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ $BASIC_SIZE -lt $PRO_SIZE ]]; then
        pass "Basic PDF (${BASIC_SIZE}B) < Professional PDF (${PRO_SIZE}B)"
    else
        fail "Expected Basic PDF < Professional PDF (${BASIC_SIZE}B >= ${PRO_SIZE}B)"
    fi
fi

if [[ $PRO_SIZE -gt 0 && $NIS2_SIZE -gt 0 ]]; then
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    if [[ $PRO_SIZE -le $NIS2_SIZE ]]; then
        pass "Professional PDF (${PRO_SIZE}B) <= NIS2 PDF (${NIS2_SIZE}B)"
    else
        fail "Expected Professional PDF <= NIS2 PDF (${PRO_SIZE}B > ${NIS2_SIZE}B)"
    fi
fi

# ── Final summary ────────────────────────────────────────────────────
header "Test Summary"

PASSED=$((TOTAL_CHECKS - FAILURES))
echo ""
echo -e "  ${GREEN}Passed:${NC} ${PASSED}"
echo -e "  ${RED}Failed:${NC} ${FAILURES}"
echo -e "  ${BOLD}Total:${NC}  ${TOTAL_CHECKS}"
echo ""

if [[ $FAILURES -eq 0 ]]; then
    echo -e "  ${GREEN}${BOLD}All checks passed!${NC}"
    exit 0
else
    echo -e "  ${RED}${BOLD}${FAILURES} check(s) failed.${NC}"
    exit 1
fi
