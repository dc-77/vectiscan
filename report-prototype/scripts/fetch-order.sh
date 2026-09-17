#!/usr/bin/env bash
# Lädt alle Report-relevanten Daten einer Order aus der VectiScan-API.
# Aufruf:  scripts/fetch-order.sh <orderId> [label]
# Zugangsdaten: report-prototype/vectiscan.creds (Zeile 1 E-Mail, Zeile 2 Passwort)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${VECTISCAN_API:-https://scan-api.vectigal.tech}"
ORDER="${1:?orderId fehlt}"
LABEL="${2:-$ORDER}"
CREDS="$ROOT/vectiscan.creds"
[ -f "$CREDS" ] || { echo "Fehlt: $CREDS" >&2; exit 1; }
EMAIL="$(sed -n '1p' "$CREDS" | tr -d '\r')"
PASS="$(sed -n '2p' "$CREDS" | tr -d '\r')"
OUT="$ROOT/input/$LABEL"
mkdir -p "$OUT/screenshots"

TOKEN="$(python3 - "$API" "$EMAIL" "$PASS" <<'PY'
import json, sys, urllib.request
api, email, pw = sys.argv[1:4]
req = urllib.request.Request(api + "/api/auth/login",
    data=json.dumps({"email": email, "password": pw}).encode(),
    headers={"Content-Type": "application/json"})
with urllib.request.urlopen(req, timeout=30) as r:
    print(json.load(r)["data"]["token"])
PY
)"
AUTH="Authorization: Bearer $TOKEN"

for ep in "" findings correlation results events report-versions; do
  name="${ep:-order}"
  url="$API/api/orders/$ORDER${ep:+/$ep}"
  curl -sS -f -H "$AUTH" "$url" -o "$OUT/$name.json" && echo "ok  $name.json ($(wc -c <"$OUT/$name.json") B)" || echo "FEHLER $name"
done
curl -sS -f -H "$AUTH" "$API/api/orders/$ORDER/report" -o "$OUT/report-current.pdf" && echo "ok  report-current.pdf ($(wc -c <"$OUT/report-current.pdf") B)" || echo "FEHLER report.pdf"

# Screenshot-Keys aus order.json + findings.json extrahieren und laden
python3 - "$OUT" "$ORDER" > "$OUT/screenshot-keys.txt" <<'PY'
import re, sys, pathlib
out, order = sys.argv[1], sys.argv[2]
keys = set()
for f in ("order.json", "findings.json"):
    p = pathlib.Path(out) / f
    if p.exists():
        keys |= set(re.findall(re.escape(order) + r"/([a-z0-9._-]{1,128})\.png", p.read_text(errors="ignore"), re.I))
print("\n".join(sorted(keys)))
PY
while read -r safe; do
  [ -n "$safe" ] || continue
  curl -sS -f -H "$AUTH" "$API/api/orders/$ORDER/screenshot/$safe" -o "$OUT/screenshots/$safe.png" && echo "ok  screenshots/$safe.png" || echo "FEHLER screenshot $safe"
done < "$OUT/screenshot-keys.txt"
echo "fertig: $OUT"
