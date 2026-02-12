FROM node:18-alpine

# Build deps for better-sqlite3 native compilation
RUN apk add --no-cache python3 make g++

WORKDIR /usr/src/app
COPY package.json package-lock.json* ./
RUN npm install --production

COPY server.js ./
COPY public ./public

# ensure the data directory exists
RUN mkdir -p ./data && chown -R node:node /usr/src/app

USER node

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/health || exit 1

CMD ["npm", "start"]
