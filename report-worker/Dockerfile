FROM debian:bookworm-slim

# upgrade -y zieht Sicherheits-Patches der Basis mit (z.B. libgnutls30
# CVE-2026-33845/42010, vom Trivy-Scan erkannt). Kombiniert mit den
# Python-Pakten in einem RUN-Layer.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      fonts-dejavu-core fonts-dejavu-extra && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r vectiscan && useradd -r -g vectiscan -m vectiscan

WORKDIR /app

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

USER vectiscan

CMD ["python3", "-m", "reporter"]
