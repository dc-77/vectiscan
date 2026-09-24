#!/usr/bin/env bash
# Spiegelt die Fremdabbilder nach ghcr.io/dc-77/vectiscan/<name>:<tag>.
#
# Laeuft als CI-Job ops-mirror-images auf dem Produktionshost (Shell-Runner) nach
# `docker login ghcr.io`. Liegt ein Abbild dort schon lokal vor (es laeuft gerade),
# wird genau dieses gespiegelt und nichts neu gezogen: gepinnt wird der Stand, der
# in Produktion laeuft, keine stille Aktualisierung. Nur fehlende Abbilder werden
# von der Quelle gezogen.
#
# Ausgabe je Abbild: Quelle | Ziel | Digest im eigenen Registry. Die Digests
# gehoeren danach in docker-compose.yml, docker-compose.dev.yml und
# scan-worker/tests/integration/docker-compose.zap-it.yml
# (Form ghcr.io/dc-77/vectiscan/<name>:<tag>@sha256:<digest>).
#
# Aufruf: bash scripts/ops/mirror-images.sh <ausgabedatei>
#
# Neues Fremdabbild oder neue Version: Zeile hier eintragen, Job laufen lassen,
# Digest in die Compose-Datei, tests/test_compose_images.py prueft die Zuordnung.
set -euo pipefail

DEST="ghcr.io/dc-77/vectiscan"
OUT="${1:-mirror-images/digests.txt}"
mkdir -p "$(dirname "${OUT}")"
: > "${OUT}"

# Quelle|Ziel (Name:Tag unter ghcr.io/dc-77/vectiscan/)
MIRRORS="
quay.io/minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e|minio:RELEASE.2025-09-07T16-13-09Z
lissy93/web-check:2.1.9@sha256:fa26f4dc781a187fb3f9e4958c7faee29af628e2fc78a335930e0c3ad28d5acd|web-check:2.1.9
zaproxy/zap-stable:2.17.0|zap-stable:2.17.0
postgres:16.4-alpine|postgres:16.4-alpine
postgres:16|postgres:16
redis:7.4-alpine|redis:7.4-alpine
redis:7|redis:7
louislam/uptime-kuma:1.23.16|uptime-kuma:1.23.16
grafana/loki:2.9.8|loki:2.9.8
grafana/promtail:2.9.8|promtail:2.9.8
grafana/grafana:11.1.0|grafana:11.1.0
twentycrm/twenty:v2.9.0|twenty:v2.9.0
quay.io/keycloak/keycloak:26.1|keycloak:26.1
quay.io/oauth2-proxy/oauth2-proxy:v7.7.1|oauth2-proxy:v7.7.1
python:3.12-slim|python:3.12-slim
"

FEHLER=0
while IFS='|' read -r SRC TARGET; do
  [ -z "${SRC}" ] && continue
  echo "=== ${SRC} -> ${DEST}/${TARGET}"
  if docker image inspect "${SRC}" >/dev/null 2>&1; then
    echo "lokal vorhanden, Image-ID $(docker image inspect --format '{{.Id}}' "${SRC}")"
  elif ! docker pull "${SRC}"; then
    echo "FEHLER: ${SRC} weder lokal noch ziehbar"
    FEHLER=1
    continue
  fi
  docker tag "${SRC}" "${DEST}/${TARGET}"
  docker push "${DEST}/${TARGET}" >/dev/null
  NAME="${TARGET%%:*}"
  DIGEST=$(docker image inspect --format '{{range .RepoDigests}}{{println .}}{{end}}' "${DEST}/${TARGET}" \
    | grep "^${DEST}/${NAME}@" | head -1 | cut -d@ -f2)
  if [ -z "${DIGEST}" ]; then
    echo "FEHLER: kein Digest fuer ${DEST}/${TARGET}"
    FEHLER=1
    continue
  fi
  echo "${SRC}|${DEST}/${TARGET}|${DIGEST}" | tee -a "${OUT}"
  if [ "${NAME}" = "minio" ]; then
    echo "Labels: $(docker image inspect --format '{{json .Config.Labels}}' "${SRC}")"
  fi
done <<< "${MIRRORS}"

echo "=== Ergebnis (${OUT})"
cat "${OUT}"
exit "${FEHLER}"
