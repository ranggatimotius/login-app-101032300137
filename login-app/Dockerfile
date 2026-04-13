# ─── Stage 1: Builder ────────────────────────────────────────
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files dan install dependencies
COPY package*.json ./
RUN npm ci --only=production

# ─── Stage 2: Production ─────────────────────────────────────
FROM node:20-alpine

# Install openssl untuk generate SSL cert
RUN apk add --no-cache openssl

WORKDIR /app

# Copy node_modules dari builder
COPY --from=builder /app/node_modules ./node_modules

# Copy source code
COPY package*.json ./
COPY src/ ./src/

# Generate SSL self-signed certificate saat build
RUN mkdir -p /app/ssl && \
    openssl req -x509 \
      -newkey rsa:4096 \
      -keyout /app/ssl/server.key \
      -out /app/ssl/server.cert \
      -days 365 \
      -nodes \
      -subj "/C=ID/ST=Jakarta/L=Jakarta/O=SecureApp-101032300137/OU=IT/CN=localhost"

# Non-root user untuk keamanan
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodeapp -u 1001 -G nodejs && \
    chown -R nodeapp:nodejs /app
USER nodeapp

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
  CMD wget -qO- --no-check-certificate https://localhost:3000/ 2>&1 | grep -q "Login\|Redirect" || exit 1

CMD ["node", "src/app.js"]
