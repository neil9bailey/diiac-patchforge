FROM node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV PATCHFORGE_DEFAULT_TENANT=diiac.io

# Apply the Bookworm PCRE2 security update without changing the pinned base.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libpcre2-8-0 \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm ci --omit=dev \
    && rm -rf /usr/local/lib/node_modules/npm /opt/yarn-v1.22.22 \
    && rm -f /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/yarn /usr/local/bin/yarnpkg

COPY . ./backend-api
COPY customer-config-default ./customer-config/default

RUN mkdir -p /app/customer-config/default/patchforge \
    && chown -R node:node /app/customer-config/default/patchforge

EXPOSE 8080

USER node

CMD ["node", "backend-api/server.js"]
