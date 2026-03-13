#!/usr/bin/env bash
# =============================================================================
# VectiScan — Server-Setup für vectigal-docker02
# =============================================================================
# Dieses Script bereitet den Server für das erste Deployment vor.
# Ausführen auf vectigal-docker02 als root oder mit sudo.
# =============================================================================

set -euo pipefail

APP_NAME="vectiscan"
DEPLOY_PATH="/opt/apps/${APP_NAME}"
REGISTRY="git-extern.bergersysteme.com:5050"
COMPOSE_URL=""  # wird lokal kopiert

# Farben
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

prompt() {
    local var_name="$1" prompt_text="$2" default="${3:-}"
    if [[ -n "$default" ]]; then
        read -rp "$(echo -e "${CYAN}${prompt_text}${NC} [${default}]: ")" input
        eval "$var_name='${input:-$default}'"
    else
        read -rp "$(echo -e "${CYAN}${prompt_text}${NC}: ")" input
        [[ -z "$input" ]] && error "Eingabe darf nicht leer sein."
        eval "$var_name='$input'"
    fi
}

prompt_secret() {
    local var_name="$1" prompt_text="$2"
    read -srp "$(echo -e "${CYAN}${prompt_text}${NC}: ")" input
    echo
    [[ -z "$input" ]] && error "Eingabe darf nicht leer sein."
    eval "$var_name='$input'"
}

echo ""
echo -e "${CYAN}=============================================${NC}"
echo -e "${CYAN}  VectiScan — Server-Setup                  ${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""

# -----------------------------------------------------------------------------
# 1. Root-Check
# -----------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    error "Bitte als root ausführen oder mit sudo."
fi

# -----------------------------------------------------------------------------
# 2. Deploy-Verzeichnis anlegen
# -----------------------------------------------------------------------------
info "Erstelle Deploy-Verzeichnis: ${DEPLOY_PATH}"
mkdir -p "${DEPLOY_PATH}"
ok "Verzeichnis erstellt."

# -----------------------------------------------------------------------------
# 3. docker-compose.yml kopieren
# -----------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_SOURCE="${SCRIPT_DIR}/../docker-compose.yml"

if [[ -f "$COMPOSE_SOURCE" ]]; then
    cp "$COMPOSE_SOURCE" "${DEPLOY_PATH}/docker-compose.yml"
    ok "docker-compose.yml kopiert."
else
    warn "docker-compose.yml nicht gefunden unter ${COMPOSE_SOURCE}"
    prompt COMPOSE_SOURCE "Pfad zur docker-compose.yml angeben"
    cp "$COMPOSE_SOURCE" "${DEPLOY_PATH}/docker-compose.yml"
    ok "docker-compose.yml kopiert."
fi

# -----------------------------------------------------------------------------
# 4. .env-Datei erstellen
# -----------------------------------------------------------------------------
echo ""
info "Erstelle .env-Datei..."
echo ""

prompt DB_NAME     "Datenbank-Name"          "vectiscan"
prompt DB_USER     "Datenbank-User"          "vectiscan"
prompt_secret DB_PASSWORD "Datenbank-Passwort"

echo ""
prompt MINIO_ACCESS_KEY "MinIO Access Key"   "vectiscan"
prompt_secret MINIO_SECRET_KEY "MinIO Secret Key"

echo ""
prompt_secret ANTHROPIC_API_KEY "Anthropic API Key (für Report-Worker)"

cat > "${DEPLOY_PATH}/.env" <<EOF
# VectiScan — Environment Variables
# Generiert am $(date '+%Y-%m-%d %H:%M:%S')

# PostgreSQL
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASSWORD}

# MinIO (S3-kompatibel)
MINIO_ACCESS_KEY=${MINIO_ACCESS_KEY}
MINIO_SECRET_KEY=${MINIO_SECRET_KEY}

# Anthropic (Report-Worker)
ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY}

# Image-Tag (wird von CI/CD gesetzt)
TAG=latest
EOF

chmod 600 "${DEPLOY_PATH}/.env"
ok ".env erstellt und Berechtigungen gesetzt (600)."

# -----------------------------------------------------------------------------
# 5. Docker-Netzwerk proxy-net sicherstellen
# -----------------------------------------------------------------------------
echo ""
info "Prüfe Docker-Netzwerk 'proxy-net'..."

if docker network ls --format '{{.Name}}' | grep -q '^proxy-net$'; then
    ok "proxy-net existiert bereits."
else
    docker network create proxy-net
    ok "proxy-net erstellt."
fi

# -----------------------------------------------------------------------------
# 6. Registry-Login
# -----------------------------------------------------------------------------
echo ""
info "Docker-Registry-Login: ${REGISTRY}"

if docker login "${REGISTRY}" 2>/dev/null; then
    ok "Registry-Login erfolgreich."
else
    warn "Registry-Login fehlgeschlagen. Bitte manuell einloggen:"
    echo "  docker login ${REGISTRY}"
fi

# -----------------------------------------------------------------------------
# 7. Zusammenfassung
# -----------------------------------------------------------------------------
echo ""
echo -e "${GREEN}=============================================${NC}"
echo -e "${GREEN}  Setup abgeschlossen!                       ${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "  Deploy-Pfad:      ${CYAN}${DEPLOY_PATH}${NC}"
echo -e "  docker-compose:   ${CYAN}${DEPLOY_PATH}/docker-compose.yml${NC}"
echo -e "  .env:             ${CYAN}${DEPLOY_PATH}/.env${NC}"
echo -e "  Netzwerk:         ${CYAN}proxy-net${NC}"
echo ""
echo -e "  ${YELLOW}Nächster Schritt:${NC}"
echo -e "  Merge nach main → Pipeline deployt automatisch."
echo -e "  Oder manuell testen:"
echo -e "    cd ${DEPLOY_PATH} && docker compose pull && docker compose up -d"
echo ""
