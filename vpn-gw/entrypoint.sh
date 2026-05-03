#!/bin/sh
# vpn-gw entrypoint — startet Tinyproxy + control-api parallel.
set -e

# Verzeichnisse fuer Tinyproxy
mkdir -p /var/log/tinyproxy /run/tinyproxy
chown -R tinyproxy:tinyproxy /var/log/tinyproxy /run/tinyproxy

# Tinyproxy im Hintergrund
tinyproxy -d -c /etc/tinyproxy/tinyproxy.conf &
TINY_PID=$!

# Control-API im Vordergrund (PID 1 = Container leben/sterben)
exec uvicorn --app-dir /opt control-api:app --host 0.0.0.0 --port 8080
