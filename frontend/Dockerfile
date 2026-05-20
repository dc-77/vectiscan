# Build stage
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_API_URL=https://scan-api.vectigal.tech
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
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
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
USER vectiscan
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
