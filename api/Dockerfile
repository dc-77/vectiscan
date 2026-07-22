# Build stage
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
RUN npm run build

# Production stage
FROM node:22-slim
# Sicherheits-Patches gegen aktuelle CVEs in der Debian-Basis (z.B.
# libgnutls30 CVE-2026-33845/42010, vom Trivy-Scan erkannt). Wird bei
# jedem Build neu ausgefuehrt — kostet ~30s, reduziert CRITICAL-CVEs.
RUN apt-get update && \
    apt-get upgrade -y && \
    rm -rf /var/lib/apt/lists/*
RUN groupadd -r vectiscan && useradd -r -g vectiscan -m vectiscan
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
# Trivy-Fix (CVE-2026-59873): das im node:22-slim gebuendelte globale npm bringt
# ein verwundbares node-tar mit (DoS via gzip-bomb, fixed in 7.5.19). npm wird zur
# Laufzeit nicht gebraucht (CMD = node dist/server.js) -> aus dem Runtime-Image
# entfernen, damit die Datei (und der CRITICAL-Trivy-Fund) verschwindet.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
COPY --from=builder /app/dist ./dist
COPY src/migrations ./dist/migrations
# Demo-Seed-Fixtures (VEC-121/PA-6): seed-demo.js liest die JSON-Fixtures zur
# Laufzeit via fs.readFileSync(__dirname/demo-data/*.json). tsc emittiert keine
# .json — daher explizit ins dist kopieren, analog zu den Migrationen.
COPY src/scripts/demo-data ./dist/scripts/demo-data
USER vectiscan
EXPOSE 4000
CMD ["node", "dist/server.js"]
