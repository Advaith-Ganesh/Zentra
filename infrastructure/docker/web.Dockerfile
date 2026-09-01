# =============================================================================
# Zentra web image (Next.js standalone output)
# =============================================================================
# Optional additional trust roots, for networks that terminate TLS on an
# inspecting proxy. Empty by default, so this is a no-op in normal builds.
FROM node:22-bookworm-slim AS certs
COPY infrastructure/docker/certs/ /usr/local/share/ca-certificates/
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -f /usr/local/share/ca-certificates/README.md \
    && update-ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM node:22-bookworm-slim AS deps
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

FROM node:22-bookworm-slim AS build
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY --from=deps /app/node_modules ./node_modules
COPY apps/web ./
# NEXT_PUBLIC_* values are inlined at build time.
ARG NEXT_PUBLIC_API_URL=http://localhost:8000
ARG NEXT_PUBLIC_APP_URL=http://localhost:3000
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL \
    NEXT_PUBLIC_APP_URL=$NEXT_PUBLIC_APP_URL
RUN npm run build

FROM node:22-bookworm-slim AS runtime
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    # Next's standalone server binds to $HOSTNAME, which defaults to the
    # container ID. Bind to all interfaces so the health check and the platform
    # router can both reach it.
    HOSTNAME=0.0.0.0
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zentra

COPY --from=build --chown=zentra:zentra /app/.next/standalone ./
COPY --from=build --chown=zentra:zentra /app/.next/static ./.next/static
COPY --from=build --chown=zentra:zentra /app/public ./public

USER zentra
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/ || exit 1

CMD ["node", "server.js"]
