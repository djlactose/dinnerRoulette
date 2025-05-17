FROM node:18-alpine

WORKDIR /usr/src/app
COPY package.json package-lock.json* ./
RUN npm install --production

COPY server.js ./
COPY public ./public

# ensure the data directory exists
RUN mkdir -p ./data

EXPOSE 8080
CMD ["npm", "start"]
