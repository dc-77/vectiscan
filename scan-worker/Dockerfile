FROM debian:bookworm-slim AS gotools

# ── 0. Go-Werkzeuge aus dem Quelltext (07.10.2026) ──────────────────
# Die Release-Binaries von subfinder, dnsx, gobuster, httpx und ffuf sind mit
# Go 1.21 bis 1.25.1 gebaut und tragen kritische Luecken der Go-Laufzeit
# (CVE-2025-68121 in crypto/tls, bei ffuf zusaetzlich CVE-2024-24790). Fuer
# subfinder, dnsx und gobuster gibt es kein Release mit reparierter Laufzeit,
# und ein Sprung auf neuere Versionen der uebrigen haette das Verhalten der
# Scans veraendert.
# Deshalb DIESELBEN Versionen wie bisher mit aktuellem Go bauen: Version und
# Hilfetext sind gleich, nur die Laufzeit ist neu. Probebau in WSL am
# 07.10.2026: Trivy 0.75 meldet fuer die fuenf Binaries 0 kritische Befunde
# statt 6. Go kommt wie die anderen Werkzeuge per curl, mit Pruefsumme, damit
# kein weiteres Image von Docker Hub gezogen werden muss.
ARG GO_VERSION=1.27.1
ARG GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates curl && \
    rm -rf /var/lib/apt/lists/* && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz && \
    echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - && \
    tar -C /usr/local -xzf /tmp/go.tgz && \
    rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:${PATH}" \
    GOBIN=/out CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
# ffuf haengt ohne den leeren VERSION_APPENDIX "-dev" an seine Version, das
# Release setzt ihn genauso.
RUN go install -ldflags "-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.13.0 && \
    go install -ldflags "-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3 && \
    go install -ldflags "-s -w" github.com/OJ/gobuster/v3@v3.8.2 && \
    go install -ldflags "-s -w" github.com/projectdiscovery/httpx/cmd/httpx@v1.6.10 && \
    go install -ldflags "-s -w -X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION_APPENDIX=" github.com/ffuf/ffuf/v2@v2.1.0 && \
    ls -l /out

FROM debian:bookworm-slim

LABEL maintainer="VectiScan" \
      description="Scan-Worker with security scanning tools"

# ── 1. System packages ──────────────────────────────────────────────
# upgrade -y zieht Sicherheits-Patches der Basis mit (z.B. libgnutls30
# CVE-2026-33845/42010, vom Trivy-Scan erkannt).
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget unzip jq dnsutils git bash \
      python3 python3-pip python3-venv \
      nmap openssl libnet-ssleay-perl libjson-perl libxml-writer-perl \
      procps bsdmainutils coreutils \
      chromium \
      whois ldnsutils && \
    rm -rf /var/lib/apt/lists/*

# Chromium fuer Playwright (Screenshots) und den Selbsttest in diagnose.py
ENV CHROME_PATH="/usr/bin/chromium"
ENV CHROMIUM_PATH="/usr/bin/chromium"
ENV PLAYWRIGHT_BROWSERS_PATH="/opt/pw-browsers"

# ── 2. Werkzeuge — feste Versionen ──────────────────────────────────
# subfinder v2.13.0, dnsx v1.2.3, gobuster v3.8.2, ffuf v2.1.0 (MIT) aus der
# Stufe gotools, httpx v1.6.10 weiter unten (nach pip, siehe dort).
COPY --from=gotools /out/subfinder /out/dnsx /out/gobuster /out/ffuf /usr/local/bin/

# Entfernt am 07.10.2026: nuclei (samt Templates), dalfox, gowitness und
# katana. Keine Scan-Phase ruft sie mehr auf: Sie stehen in keiner
# Werkzeugliste in scanner/packages.py, und Screenshots macht Playwright. Ihre
# Binaries brachten aber 7 der 13 kritischen Trivy-Befunde mit, die
# nuclei-Templates dazu einen Fehlalarm "gcp-service-account" (ein Suchmuster,
# kein Schluessel). tests/test_dockerfile.py prueft, dass kein Paket sie braucht.

# amass v5 entfernt (F-P0B-003, 2026-05-07): Hard-Cap-Bottleneck (300s) +
# `-brute`-Doppelarbeit zu gobuster_dns mit der ~30k-Merged-Wordlist
# (siehe F-P0B-004). <5% Subdomain-Coverage-Verlust durch Wegfall der
# amass-Permutation-Heuristik; -50MB Image-Groesse.

# feroxbuster v2.11.0 (MIT)
RUN curl -fsSL https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.tar.gz \
      -o /tmp/feroxbuster.tar.gz && \
    tar xzf /tmp/feroxbuster.tar.gz -C /usr/local/bin/ feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm -f /tmp/feroxbuster.tar.gz

# exploitdb/searchsploit (GPL v2 — local search only, no code linking)
# Config goes to /home/scanner/.searchsploit_rc (scanner user's HOME)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    mkdir -p /home/scanner && \
    cp /opt/exploitdb/.searchsploit_rc /home/scanner/.searchsploit_rc 2>/dev/null || true && \
    sed -i 's|/opt/exploitdb-papers|/opt/exploitdb/exploitdb-papers|g; s|/opt/exploitdb-bin-sploits|/opt/exploitdb/exploitdb-bin-sploits|g' /home/scanner/.searchsploit_rc 2>/dev/null || true

# ── 3. testssl.sh ───────────────────────────────────────────────────
# VEC-373: STABILEN Release-Tag pinnen, NICHT den Default-Branch klonen.
# Der Default-Branch ist `3.3dev` (instabiler Dev-Branch). Dort hat das
# Option-Parsing einen Bug: das Case-Pattern fuer `--connect-timeout`
# (Space-Form `--connect-timeout 10`) ist durch ein fehlendes `|` mit
# `--socket-timeout` verklebt → testssl behandelt `--connect-timeout` als
# unrecognized option, druckt den Usage-Banner und beendet mit Exit 1.
# Exit 1 liegt im "ok"-Bereich → der Fehler wurde still durchgereicht
# (leeres JSON → keine SSL-Findings → AI-Halluzination "HSTS max-age=0").
# v3.2.3 hat korrektes Parsing fuer alle von uns genutzten Flags.
RUN git clone --depth 1 --branch v3.2.3 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
ENV PATH="/opt/testssl.sh:${PATH}"

# ── 3b. nikto (not in bookworm-slim repos) ────────────────────────
RUN git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto && \
    ln -s /opt/nikto/program/nikto.pl /usr/local/bin/nikto
ENV PATH="/opt/nikto/program:${PATH}"

# ── 3c. WPScan — Ruby-based WordPress scanner ────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends ruby ruby-dev build-essential libcurl4-openssl-dev zlib1g-dev && \
    gem install wpscan --no-document && \
    apt-get purge -y build-essential ruby-dev && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# ── 4. Python packages (wafw00f only — webtech installed after requirements.txt) ──
RUN pip3 install --no-cache-dir --break-system-packages wafw00f

# ── 5. Wordlists ───────────────────────────────────────────────────
# SecLists Industriestandard fuer Web-Discovery + Pentesting:
#   common.txt              ~4.6k   Standard-Web-Pfade
#   raft-small-files.txt    ~10k    Sensitive-Files (.env, .git, backup.zip, dump.sql, ...)
#                                   S0a: von phase2.WORDLIST_MAP/FFUF_WORDLISTS erwartet.
#                                   F-PH2-001 stellte den Code auf small um, das Image blieb
#                                   auf medium -> ffuf_sensitive wurde immer uebersprungen.
#   raft-medium-files.txt   ~17.5k  Vorgaenger, bleibt fuer Ad-hoc-Laeufe im Image
#   subdomains-top1m-5000   5k      DNS-Bruteforce
#   burp-parameter-names    6.5k    HTTP-Parameter-Discovery
#   CMS/wp-plugins.fuzz     ~4k     WordPress-Plugin-Pfade
RUN mkdir -p /usr/share/wordlists /usr/share/wordlists/seclists/Discovery/Web-Content \
             /usr/share/wordlists/seclists/Discovery/DNS \
             /usr/share/wordlists/seclists/Discovery/Web-Content/CMS && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
      -o /usr/share/wordlists/subdomains-top5000.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
      -o /usr/share/wordlists/common.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
      -o /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt \
      -o /usr/share/wordlists/raft-medium-files.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-files.txt \
      -o /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt \
      -o /usr/share/wordlists/raft-small-files.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-files.txt \
      -o /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
      -o /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt \
      -o /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt \
      -o /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt

# Curated wordlists for AI-adaptive scanning
COPY wordlists/wordpress.txt /usr/share/wordlists/wordpress.txt
COPY wordlists/api-endpoints.txt /usr/share/wordlists/api-endpoints.txt
COPY wordlists/cms-common.txt /usr/share/wordlists/cms-common.txt

# S0a Build-Gate: ein stiller curl-Fehler oben hat frueher erst zur Laufzeit
# als "wordlist_missing"-Skip gewirkt (ffuf_sensitive: 0 Treffer in 42 Scans).
# Jede Datei, die scanner/preflight.py beim Start erwartet, muss hier existieren
# und nicht leer sein -- sonst bricht der Build statt spaeter der Scan.
RUN set -eu; for f in \
      /usr/share/wordlists/common.txt \
      /usr/share/wordlists/wordpress.txt \
      /usr/share/wordlists/api-endpoints.txt \
      /usr/share/wordlists/cms-common.txt \
      /usr/share/wordlists/raft-small-files.txt \
      /usr/share/wordlists/subdomains-top5000.txt \
      /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
      /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-files.txt \
      /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt \
      /usr/share/wordlists/seclists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt \
      /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt; \
    do test -s "$f" || { echo "Wordlist fehlt oder ist leer: $f" >&2; exit 1; }; done

# F-P0B-004 (2026-05-07): Merged DNS-Bruteforce-Wordlist fuer gobuster_dns
# Quellen (alle deduplikat-gemerged via `sort -u`):
#   1. SecLists subdomains-top1million-20000.txt        (~20k klassische Patterns)
#   2. bitquark_20160227_subdomains_popular_1000000     (Top-10k, Bug-Bounty-derived)
#   3. n0kovo_subdomains_small.txt                      (~10k frisch 2024 gepflegt)
# Erwartete Endgroesse ~28-32k Eintraege (typische Ueberschneidung 20-30%).
# Loest die zu enge `subdomains-top5000.txt`-Liste fuer gobuster_dns ab.
RUN mkdir -p /opt/wordlists \
 && curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt \
      -o /tmp/seclists.txt \
 && curl -fsSL https://raw.githubusercontent.com/bitquark/dnspop/master/results/bitquark_20160227_subdomains_popular_1000000 \
      | head -10000 > /tmp/bitquark.txt \
 && curl -fsSL https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_small.txt \
      -o /tmp/n0kovo.txt \
 && cat /tmp/seclists.txt /tmp/bitquark.txt /tmp/n0kovo.txt | sort -u > /opt/wordlists/dns-merged-30k.txt \
 && rm /tmp/seclists.txt /tmp/bitquark.txt /tmp/n0kovo.txt \
 && test -s /opt/wordlists/dns-merged-30k.txt

# ── 6. Scanner code ────────────────────────────────────────────────
WORKDIR /opt/scanner

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
    pip3 install --no-cache-dir --break-system-packages webtech && \
    pip3 install --no-cache-dir --break-system-packages playwright && \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers playwright install chromium --with-deps

# httpx v1.6.10 — MUST come after pip install because anthropic pulls Python
# httpx which installs an entry-point script that shadows the Go binary.
# Gebaut in der Stufe gotools (siehe oben).
COPY --from=gotools /out/httpx /usr/local/bin/httpx

COPY scanner/ /opt/scanner/scanner/
# F-PRE-003: Generated-Cloud-Provider-Ranges (sync via scripts/sync-cloud-ranges.py)
# Optionales Verzeichnis — bei frischem Checkout ohne Sync-Lauf existiert
# nur __init__.py + Loader faellt im saas_heuristic auf _STATIC_RANGES zurueck.
COPY data/ /opt/scanner/data/

# ── 7. Verification ────────────────────────────────────────────────
RUN nmap --version; \
    subfinder -version; \
    gobuster --help > /dev/null; \
    dnsx -version; \
    /opt/testssl.sh/testssl.sh --help || true; \
    perl /opt/nikto/program/nikto.pl -Version || true; \
    wafw00f --version; \
    webtech --help || true; \
    httpx -version; \
    wpscan --version; \
    ffuf -V; \
    feroxbuster --version; \
    searchsploit --help > /dev/null 2>&1 || true; \
    echo "All tools verified"

# ── 8. Security — non-root user ────────────────────────────────────
RUN useradd -r -s /bin/false scanner && \
    mkdir -p /home/scanner/.config/subfinder && \
    chown -R scanner:scanner /opt/scanner /home/scanner /opt/exploitdb

USER scanner
ENTRYPOINT ["python3", "-m", "scanner"]
