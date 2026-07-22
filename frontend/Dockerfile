# Build stage
FROM node:22-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
ARG NEXT_PUBLIC_API_URL=https://scan-api.vectigal.tech
ENV NEXT_PUBLIC_API_URL=${NEXT_PUBLIC_API_URL}
# VEC-190: Cloudflare-Turnstile-Site-Key (öffentlich, im Client-JS sichtbar) zur
# Build-Zeit ins Next.js-Bundle inlinen. Default leer → Widget bleibt inert
# (WebCheckFreeForm blendet ohne Key aus). CI reicht den Wert via --build-arg aus
# der CI/CD-Var NEXT_PUBLIC_TURNSTILE_SITE_KEY durch (siehe .gitlab-ci.yml).
ARG NEXT_PUBLIC_TURNSTILE_SITE_KEY=""
ENV NEXT_PUBLIC_TURNSTILE_SITE_KEY=${NEXT_PUBLIC_TURNSTILE_SITE_KEY}
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
# Trivy-Fix (CVE-2026-59873): gebuendeltes globales npm (verwundbares node-tar,
# fixed in 7.5.19) aus dem Runtime-Image entfernen — Next.js Standalone laeuft mit
# `node server.js`, npm wird nie gebraucht.
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
USER vectiscan
EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"
CMD ["node", "server.js"]
