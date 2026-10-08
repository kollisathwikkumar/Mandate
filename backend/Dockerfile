ARG NODE_BASE_IMAGE=node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392

FROM ${NODE_BASE_IMAGE} AS build

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
RUN npm rebuild @foundry-rs/anvil --foreground-scripts
COPY . .
RUN npm run build

FROM build AS production-dependencies
RUN npm prune --omit=dev --ignore-scripts

FROM ${NODE_BASE_IMAGE} AS runtime
ENV NODE_ENV=production
WORKDIR /app
COPY --from=production-dependencies --chown=node:node /app/package.json ./package.json
COPY --from=production-dependencies --chown=node:node /app/package-lock.json ./package-lock.json
COPY --from=production-dependencies --chown=node:node /app/node_modules ./node_modules
COPY --from=production-dependencies --chown=node:node /app/dist ./dist
COPY --from=production-dependencies --chown=node:node /app/migrations ./migrations
USER node
EXPOSE 3000 3100
ENTRYPOINT ["node", "--import", "./dist/packages/observability/src/register.js"]
CMD ["dist/apps/api/src/server.js"]
