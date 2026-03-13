FROM debian:bookworm-slim

LABEL maintainer="VectiScan" \
      description="Scan-Worker with security scanning tools"

# ── 1. System packages ──────────────────────────────────────────────
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates curl wget unzip jq dnsutils git \
      python3 python3-pip python3-venv \
      nmap nikto sslscan openssl && \
    rm -rf /var/lib/apt/lists/*

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

# amass v5.0.1
RUN curl -fsSL https://github.com/owasp-amass/amass/releases/download/v5.0.1/amass_linux_amd64.tar.gz \
      -o /tmp/amass.tar.gz && \
    tar xzf /tmp/amass.tar.gz -C /tmp && \
    mv /tmp/amass_linux_amd64/amass /usr/local/bin/amass && \
    chmod +x /usr/local/bin/amass && \
    rm -rf /tmp/amass.tar.gz /tmp/amass_linux_amd64

# nuclei templates
RUN nuclei -update-templates

# ── 3. testssl.sh ───────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh
ENV PATH="/opt/testssl.sh:${PATH}"

# ── 4. Python packages ─────────────────────────────────────────────
RUN pip3 install --no-cache-dir --break-system-packages wafw00f webtech

# ── 5. Wordlists ───────────────────────────────────────────────────
RUN mkdir -p /usr/share/wordlists && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
      -o /usr/share/wordlists/subdomains-top5000.txt && \
    curl -fsSL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
      -o /usr/share/wordlists/common.txt

# ── 6. Scanner code ────────────────────────────────────────────────
WORKDIR /opt/scanner

COPY requirements.txt .
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

COPY scanner/ /opt/scanner/

# ── 7. Verification ────────────────────────────────────────────────
RUN nmap --version && \
    nuclei -version && \
    subfinder -version && \
    amass -version && \
    gobuster version && \
    dnsx -version && \
    gowitness version && \
    /opt/testssl.sh/testssl.sh --help || true && \
    nikto -Version && \
    wafw00f --version && \
    webtech --help

# ── 8. Security — non-root user ────────────────────────────────────
RUN useradd -r -s /bin/false scanner && \
    chown -R scanner:scanner /opt/scanner

USER scanner
ENTRYPOINT ["python3", "-m", "scanner"]
