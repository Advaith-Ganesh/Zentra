#!/usr/bin/env bash
# Wrapper around `docker compose` that points the app at the right public URLs.
#
# Locally everything is on localhost. In a browser-based GitHub Codespace it is
# not: your browser runs on your own machine, and the container's ports are
# published at https://<codespace>-<port>.app.github.dev. The frontend bakes
# NEXT_PUBLIC_API_URL in at build time, so it has to be correct before the image
# is built — hence a wrapper rather than a runtime tweak.
set -euo pipefail

if [ -n "${CODESPACE_NAME:-}" ]; then
  domain="${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-app.github.dev}"
  export APP_URL="https://${CODESPACE_NAME}-3000.${domain}"
  export API_URL="https://${CODESPACE_NAME}-8000.${domain}"
  export CORS_ALLOWED_ORIGINS="${APP_URL}"
  echo "Codespace detected. Frontend: ${APP_URL}" >&2
  echo "                    API:      ${API_URL}" >&2
  echo "Port 8000 must be set to Public for the browser to reach the API." >&2
fi

exec docker compose "$@"
