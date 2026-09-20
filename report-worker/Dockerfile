FROM debian:bookworm-slim

# upgrade -y zieht Sicherheits-Patches der Basis mit (z.B. libgnutls30
# CVE-2026-33845/42010, vom Trivy-Scan erkannt). Kombiniert mit den
# Python-Pakten in einem RUN-Layer.
# libpangoft2 zieht Pango, HarfBuzz, FreeType, Fontconfig und GLib mit; das ist
# alles, was WeasyPrint (Renderer v3, S4) an Systembibliotheken braucht. Cairo und
# gdk-pixbuf sind seit WeasyPrint 53 nicht mehr noetig, SVG zeichnet es selbst und
# Rasterbilder gehen ueber Pillow. poppler-utils ebenfalls nicht: Seitenzahl kommt
# aus WeasyPrint, die Wortzahl je Seite aus pypdf.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
      python3 python3-pip python3-venv \
      libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b libfontconfig1 \
      fonts-dejavu-core fonts-dejavu-extra && \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -r vectiscan && useradd -r -g vectiscan -m vectiscan

WORKDIR /app

COPY requirements.txt .
RUN python3 -m pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

USER vectiscan

CMD ["python3", "-m", "reporter"]
