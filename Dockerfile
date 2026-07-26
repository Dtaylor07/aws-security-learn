# ── Stage 1: build dependencies ────────────────────────────────────────────
FROM node:20-alpine AS deps
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

# ── Stage 2: final minimal image ────────────────────────────────────────────
# Use distroless-style slim base to minimise Inspector CVE surface
FROM node:20-alpine AS runner

# Security hardening
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

WORKDIR /app

# Copy only production deps + source
COPY --from=deps /app/node_modules ./node_modules
COPY src/        ./src/
COPY public/     ./public/
COPY package.json ./

# Drop privileges
USER appuser

EXPOSE 3000

# Health check aligned with ALB target group check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "src/index.js"]
