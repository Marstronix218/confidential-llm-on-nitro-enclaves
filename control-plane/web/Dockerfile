# Build context: the repo root (docker-compose.yml sets it)
# node:24.22.1-alpine
FROM node@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

WORKDIR /app

COPY control-plane/web/package.json control-plane/web/package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY control-plane/web/ ./

# Vite dev server: VITE_* variables (VITE_API_BASE_URL, VITE_API_TOKEN) are read from the
# container environment when it starts, so docker-compose.yml passes them as `environment`.
EXPOSE 8080
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
