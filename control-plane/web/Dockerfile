FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

COPY . .

EXPOSE 8080
CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
