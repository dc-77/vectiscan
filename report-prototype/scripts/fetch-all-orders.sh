#!/usr/bin/env bash
# Lädt die Orderliste und je Order findings.json + results.json (+ order.json) nach input/_all/<orderId>/.
# Aufruf: scripts/fetch-all-orders.sh [max]   Zugangsdaten: vectiscan.creds
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${VECTISCAN_API:-https://scan-api.vectigal.tech}"
MAX="${1:-500}"
CREDS="$ROOT/vectiscan.creds"
EMAIL="$(sed -n '1p' "$CREDS" | tr -d '\r')"
PASS="$(sed -n '2p' "$CREDS" | tr -d '\r')"
OUT="$ROOT/input/_all"
mkdir -p "$OUT"
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
curl -sS -f -H "$AUTH" "$API/api/orders" -o "$OUT/orders.json" || { echo "FEHLER orders"; exit 1; }
python3 - "$OUT/orders.json" <<'PY' > "$OUT/order-ids.txt"
import json,sys
d=json.load(open(sys.argv[1]))["data"]["orders"]
print("\n".join(o["id"] for o in d if o.get("hasReport")))
PY
echo "orders gesamt: $(python3 -c "import json;print(len(json.load(open('$OUT/orders.json'))['data']['orders']))"), mit Report: $(wc -l < "$OUT/order-ids.txt")"
n=0
while read -r oid; do
  [ -n "$oid" ] || continue
  n=$((n+1)); [ "$n" -le "$MAX" ] || break
  d="$OUT/$oid"; mkdir -p "$d"
  [ -s "$d/findings.json" ] || curl -sS -f -H "$AUTH" "$API/api/orders/$oid/findings" -o "$d/findings.json" || echo "FEHLER findings $oid"
  [ -s "$d/results.json" ]  || curl -sS -f -H "$AUTH" "$API/api/orders/$oid/results"  -o "$d/results.json"  || echo "FEHLER results $oid"
  [ -s "$d/order.json" ]    || curl -sS -f -H "$AUTH" "$API/api/orders/$oid"          -o "$d/order.json"    || echo "FEHLER order $oid"
done < "$OUT/order-ids.txt"
echo "fertig: $n Orders, $(du -sh "$OUT" | cut -f1)"
