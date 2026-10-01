# syntax=docker/dockerfile:1

# --- Build: install deps (better-sqlite3 is native) and compile the Tailwind CSS ---
FROM node:22-bookworm-slim AS build
WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ \
 && rm -rf /var/lib/apt/lists/*
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build:css && npm prune --omit=dev

# --- Runtime ---
FROM node:22-bookworm-slim
ENV NODE_ENV=production \
    PORT=3000 \
    DB_FILE=/app/data/app.db
WORKDIR /app
COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/src ./src
COPY --from=build --chown=node:node /app/scripts ./scripts
COPY --from=build --chown=node:node /app/views ./views
COPY --from=build --chown=node:node /app/public ./public
RUN mkdir -p /app/data && chown node:node /app/data
USER node
VOLUME ["/app/data"]
EXPOSE 3000
CMD ["node", "src/server.js"]
