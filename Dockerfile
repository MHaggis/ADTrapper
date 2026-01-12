# ADTrapper Application Dockerfile
FROM node:20-alpine

RUN apk add --no-cache libc6-compat

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

RUN mkdir -p .next uploads public && \
    chmod -R 755 .next uploads public

# Build the Next.js application
RUN npm run build

EXPOSE 3000

ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

CMD ["npm", "run", "start"]
