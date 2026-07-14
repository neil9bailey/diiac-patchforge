FROM node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS build

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html tsconfig.json vite.config.ts ./
COPY scripts ./scripts
COPY src ./src
COPY public ./public
RUN npm run build

FROM nginx:1.30.3-alpine3.23-slim@sha256:d5b51cfc7d55fc7a7bcf4d1d577b9c3738331df56d68f0b1d8ac9795b9470a5a

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080
