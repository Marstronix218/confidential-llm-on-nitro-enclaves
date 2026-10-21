# Build context: the repo root (docker-compose.yml sets it)
# node:20.20.2-alpine
FROM node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293

WORKDIR /app

COPY control-plane/web/package.json control-plane/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY control-plane/web/ ./

# Vite dev server: VITE_* variables (VITE_API_BASE_URL, VITE_API_TOKEN) are read from the
# container environment when it starts, so docker-compose.yml passes them as `environment`.
EXPOSE 8080
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
