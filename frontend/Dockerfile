# 8pi Frontend — React (CRA) build served by nginx
FROM node:20-alpine AS build

WORKDIR /app
ENV CI=true \
    GENERATE_SOURCEMAP=false \
    DISABLE_ESLINT_PLUGIN=true

# Install deps first (better caching)
COPY frontend/package.json frontend/yarn.lock ./
RUN yarn install --frozen-lockfile --network-timeout 600000

# Build
COPY frontend/ ./
# REACT_APP_BACKEND_URL is baked in at build time.
# For same-origin deployments (nginx reverse-proxies /api to backend), leave it empty
# so the frontend calls "/api/..." relative to the current host.
ARG REACT_APP_BACKEND_URL=""
ENV REACT_APP_BACKEND_URL=$REACT_APP_BACKEND_URL
RUN yarn build

# ────────────── runtime ──────────────
FROM nginx:1.27-alpine

RUN rm -rf /usr/share/nginx/html/* && \
    apk add --no-cache curl

COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost/ || exit 1
