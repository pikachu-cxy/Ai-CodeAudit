# Multi-stage build: official Node image builds the SPA, official nginx serves it.
# Build context is the monorepo root (see docker-compose.yml).
FROM node:20-bookworm-slim AS builder

WORKDIR /src

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund

# Copy only build inputs: no .env / .env.local can leak into the bundle.
COPY frontend/index.html frontend/tsconfig.json frontend/vite.config.ts \
     frontend/postcss.config.js frontend/tailwind.config.js ./
COPY frontend/src ./src

RUN npm run build

FROM nginx:1.27-alpine

# Standard official-image nginx paths (replaces the old non-standard /nginx tree).
COPY deploy/nginx/default.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /src/dist/ /usr/share/nginx/html/

EXPOSE 80

# nginx image already defines `CMD ["nginx", "-g", "daemon off;"]`.
