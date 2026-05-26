FROM node:24-bookworm-slim

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV PATCHFORGE_DEFAULT_TENANT=diiac-demo

COPY package*.json ./
RUN npm ci --omit=dev

COPY . ./backend-api
COPY customer-config-demo ./customer-config/demo

EXPOSE 8080

CMD ["node", "backend-api/server.js"]
