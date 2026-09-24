#!/usr/bin/env bash
# Zieht nur Abbilder aus der eigenen Registry ghcr.io/dc-77/vectiscan/.
#
# Aufruf im Verzeichnis mit docker-compose.yml, Profile ueber COMPOSE_PROFILES:
#   COMPOSE_PROFILES=crm bash scripts/ops/pull-own-images.sh
#
# Entscheidung DC (24.09.2026): kein pauschales `docker compose pull` mehr. Am
# 24.09. lieferte quay.io minio/minio nur noch mit Anmeldung (401), und der
# pauschale Pull riss den ganzen Deploy mit (Pipeline 3181). Fremdabbilder liegen
# gespiegelt unter ghcr.io/dc-77/vectiscan/ und sind per Digest gepinnt
# (scripts/ops/mirror-images.sh, tests/test_compose_images.py). Kein
# --ignore-pull-failures: ein Fehler beim Ziehen bleibt ein Fehler.
set -euo pipefail

PREFIX="ghcr.io/dc-77/vectiscan/"

SERVICES=$(docker compose config --format json | python3 -c "
import json, sys
services = json.load(sys.stdin)['services']
print(' '.join(sorted(n for n, s in services.items() if str(s.get('image', '')).startswith('${PREFIX}'))))
")

if [ -z "${SERVICES}" ]; then
  echo "ERROR: keine Services mit Abbild aus ${PREFIX}" >&2
  exit 1
fi

FREMD=$(docker compose config --format json | python3 -c "
import json, sys
services = json.load(sys.stdin)['services']
print(' '.join(sorted(f\"{n}={s.get('image')}\" for n, s in services.items()
                      if s.get('image') and not str(s['image']).startswith('${PREFIX}'))))
")
if [ -n "${FREMD}" ]; then
  echo "WARN: Abbilder ausserhalb von ${PREFIX} werden nicht gezogen: ${FREMD}"
fi

echo "Pull (eigene Registry): ${SERVICES}"
# shellcheck disable=SC2086
docker compose pull ${SERVICES}
