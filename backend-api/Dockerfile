FROM node:24-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV PATCHFORGE_DEFAULT_TENANT=diiac.io

COPY package*.json ./
RUN npm ci --omit=dev

COPY . ./backend-api
COPY customer-config-default ./customer-config/default

EXPOSE 8080

CMD ["node", "backend-api/server.js"]
