# vpn-gw — ExpressVPN-CLI + Tinyproxy + kleine Control-API (PR-VPN, 2026-05-03)
#
# Architektur:
# 1. Container laeuft mit cap_add: NET_ADMIN + /dev/net/tun (fuer TUN-Interface)
# 2. ExpressVPN-CLI muss separat gemounted werden (proprietaer, kein DEB-Mirror)
#    → COPY-Hook fuer expressvpn_*.deb aus build-context
# 3. Tinyproxy lauscht auf 3128 → leitet HTTP/HTTPS-Requests durch System-
#    Routing-Table (= durch ExpressVPN-Tunnel wenn connected)
# 4. control-api.py (FastAPI) auf 8080 — POST /vpn/connect?location=de etc.
#
# Fallback: wenn EXPRESSVPN_ACCESS_TOKEN-ENV nicht gesetzt UND keine .deb
# vorhanden ist, startet Tinyproxy aber ExpressVPN-CLI ist no-op. Tools
# greifen dann ueber HTTP-Proxy aber direkter Internet-Routing → kein
# Service-Bruch, einfach ohne VPN-Schutz.

FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        tinyproxy \
        iproute2 \
        iptables \
        curl \
        ca-certificates \
        python3 \
        python3-pip \
        gnupg \
        expect \
    && rm -rf /var/lib/apt/lists/*

# Optional: ExpressVPN-CLI .deb (muss in build-context liegen).
# Falls nicht vorhanden, ueberspringt der Build den Step ohne Fehler.
COPY *.deb /tmp/
RUN if ls /tmp/expressvpn*.deb 1>/dev/null 2>&1; then \
        dpkg -i /tmp/expressvpn*.deb || apt-get install -fy && \
        rm /tmp/expressvpn*.deb; \
    else \
        echo "WARN: kein ExpressVPN-DEB im build-context. vpn-gw startet ohne VPN-CLI."; \
    fi

# Python-API
RUN pip3 install --no-cache-dir --break-system-packages fastapi==0.110.0 uvicorn==0.27.0

COPY control-api.py /opt/control-api.py
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

# Tinyproxy 3128 (HTTP-Proxy fuer Tools), API 8080 (interner Control)
EXPOSE 3128 8080

ENTRYPOINT ["/opt/entrypoint.sh"]
