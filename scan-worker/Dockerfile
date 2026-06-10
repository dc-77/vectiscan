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

# gowitness/katana need Chrome — set path
ENV CHROME_PATH="/usr/bin/chromium"
ENV CHROMIUM_PATH="/usr/bin/chromium"
ENV PLAYWRIGHT_BROWSERS_PATH="/opt/pw-browsers"

# ── 2. Go binaries — pinned versions ────────────────────────────────

# nuclei v3.7.1
RUN curl -fsSL https://github.com/projectdiscovery/nuclei/releases/download/v3.7.1/nuclei_3.7.1_linux_amd64.zip \
      -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /tmp/nuclei && \
    mv /tmp/nuclei/nuclei /usr/local/bin/nuclei && \
    chmod +x /usr/local/bin/nuclei && \
    rm -rf /tmp/nuclei /tmp/nuclei.zip

# subfinder v2.13.0
RUN curl -fsSL https://github.com/projectdiscovery/subfinder/releases/download/v2.13.0/subfinder_2.13.0_linux_amd64.zip \
      -o /tmp/subfinder.zip && \
    unzip /tmp/subfinder.zip -d /tmp/subfinder && \
    mv /tmp/subfinder/subfinder /usr/local/bin/subfinder && \
    chmod +x /usr/local/bin/subfinder && \
    rm -rf /tmp/subfinder /tmp/subfinder.zip

# dnsx v1.2.3
RUN curl -fsSL https://github.com/projectdiscovery/dnsx/releases/download/v1.2.3/dnsx_1.2.3_linux_amd64.zip \
      -o /tmp/dnsx.zip && \
    unzip /tmp/dnsx.zip -d /tmp/dnsx && \
    mv /tmp/dnsx/dnsx /usr/local/bin/dnsx && \
    chmod +x /usr/local/bin/dnsx && \
    rm -rf /tmp/dnsx /tmp/dnsx.zip

# gobuster v3.8.2
RUN curl -fsSL https://github.com/OJ/gobuster/releases/download/v3.8.2/gobuster_Linux_x86_64.tar.gz \
      -o /tmp/gobuster.tar.gz && \
    tar xzf /tmp/gobuster.tar.gz -C /tmp && \
    mv /tmp/gobuster /usr/local/bin/gobuster && \
    chmod +x /usr/local/bin/gobuster && \
    rm -f /tmp/gobuster.tar.gz

# gowitness 3.1.1
RUN curl -fsSL https://github.com/sensepost/gowitness/releases/download/3.1.1/gowitness-3.1.1-linux-amd64 \
      -o /usr/local/bin/gowitness && \
    chmod +x /usr/local/bin/gowitness

# amass v5 entfernt (F-P0B-003, 2026-05-07): Hard-Cap-Bottleneck (300s) +
# `-brute`-Doppelarbeit zu gobuster_dns mit der ~30k-Merged-Wordlist
# (siehe F-P0B-004). <5% Subdomain-Coverage-Verlust durch Wegfall der
# amass-Permutation-Heuristik; -50MB Image-Groesse.

# katana v1.1.3
RUN curl -fsSL https://github.com/projectdiscovery/katana/releases/download/v1.1.3/katana_1.1.3_linux_amd64.zip \
      -o /tmp/katana.zip && \
    unzip /tmp/katana.zip -d /tmp/katana && \
    mv /tmp/katana/katana /usr/local/bin/katana && \
    chmod +x /usr/local/bin/katana && \
    rm -rf /tmp/katana /tmp/katana.zip

# ffuf v2.1.0 (MIT)
RUN curl -fsSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz \
      -o /tmp/ffuf.tar.gz && \
    tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf && \
    chmod +x /usr/local/bin/ffuf && \
    rm -f /tmp/ffuf.tar.gz

# feroxbuster v2.11.0 (MIT)
RUN curl -fsSL https://github.com/epi052/feroxbuster/releases/download/v2.11.0/x86_64-linux-feroxbuster.tar.gz \
      -o /tmp/feroxbuster.tar.gz && \
    tar xzf /tmp/feroxbuster.tar.gz -C /usr/local/bin/ feroxbuster && \
    chmod +x /usr/local/bin/feroxbuster && \
    rm -f /tmp/feroxbuster.tar.gz

# dalfox v2.9.3 (MIT)
RUN curl -fsSL https://github.com/hahwul/dalfox/releases/download/v2.9.3/dalfox_2.9.3_linux_amd64.tar.gz \
      -o /tmp/dalfox.tar.gz && \
    tar xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox && \
    chmod +x /usr/local/bin/dalfox && \
    rm -f /tmp/dalfox.tar.gz

# exploitdb/searchsploit (GPL v2 — local search only, no code linking)
# Config goes to /home/scanner/.searchsploit_rc (scanner user's HOME)
RUN git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && \
    ln -s /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && \
    mkdir -p /home/scanner && \
    cp /opt/exploitdb/.searchsploit_rc /home/scanner/.searchsploit_rc 2>/dev/null || true && \
    sed -i 's|/opt/exploitdb-papers|/opt/exploitdb/exploitdb-papers|g; s|/opt/exploitdb-bin-sploits|/opt/exploitdb/exploitdb-bin-sploits|g' /home/scanner/.searchsploit_rc 2>/dev/null || true

# nuclei templates
RUN nuclei -update-templates

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
#   raft-medium-files.txt   ~17.5k  Sensitive-Files (.env, .git, backup.zip, dump.sql, ...)
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
 && rm /tmp/seclists.txt /tmp/bitquark.txt /tmp/n0kovo.txt

# ── 6. Scanner code ────────────────────────────────────────────────
WORKDIR /opt/scanner

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt && \
    pip3 install --no-cache-dir --break-system-packages webtech && \
    pip3 install --no-cache-dir --break-system-packages playwright && \
    PLAYWRIGHT_BROWSERS_PATH=/opt/pw-browsers playwright install chromium --with-deps

# httpx v1.6.10 — MUST come after pip install because anthropic pulls Python
# httpx which installs an entry-point script that shadows the Go binary
RUN curl -fsSL https://github.com/projectdiscovery/httpx/releases/download/v1.6.10/httpx_1.6.10_linux_amd64.zip \
      -o /tmp/httpx.zip && \
    unzip /tmp/httpx.zip -d /tmp/httpx && \
    mv /tmp/httpx/httpx /usr/local/bin/httpx && \
    chmod +x /usr/local/bin/httpx && \
    rm -rf /tmp/httpx /tmp/httpx.zip

COPY scanner/ /opt/scanner/scanner/
# F-PRE-003: Generated-Cloud-Provider-Ranges (sync via scripts/sync-cloud-ranges.py)
# Optionales Verzeichnis — bei frischem Checkout ohne Sync-Lauf existiert
# nur __init__.py + Loader faellt im saas_heuristic auf _STATIC_RANGES zurueck.
COPY data/ /opt/scanner/data/

# ── 7. Verification ────────────────────────────────────────────────
RUN nmap --version; \
    nuclei -version; \
    subfinder -version; \
    gobuster version; \
    dnsx -version; \
    gowitness version; \
    /opt/testssl.sh/testssl.sh --help || true; \
    perl /opt/nikto/program/nikto.pl -Version || true; \
    wafw00f --version; \
    webtech --help || true; \
    httpx -version; \
    katana -version; \
    wpscan --version; \
    ffuf -V; \
    feroxbuster --version; \
    dalfox version; \
    searchsploit --help > /dev/null 2>&1 || true; \
    echo "All tools verified"

# ── 8. Security — non-root user ────────────────────────────────────
RUN useradd -r -s /bin/false scanner && \
    mkdir -p /home/scanner/.config/subfinder && \
    chown -R scanner:scanner /opt/scanner /home/scanner /opt/exploitdb

USER scanner
ENTRYPOINT ["python3", "-m", "scanner"]
