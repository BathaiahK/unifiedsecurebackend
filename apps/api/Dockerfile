# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy workspace files
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY packages ./packages
COPY apps/api ./apps/api

# Install pnpm and dependencies
RUN npm install -g pnpm && CI=true pnpm install --frozen-lockfile

# Generate Prisma client and build all packages (API + shared packages it depends on)
RUN CI=true pnpm db:generate && pnpm -r build

# Runtime stage
FROM node:20-alpine

WORKDIR /app

# Install pnpm for production
RUN npm install -g pnpm

# Copy workspace configuration
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Copy built artifacts and node_modules from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/packages ./packages

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:4000/health', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"

# Start the API
# Environment variables are set via Cloud Run deployment, not from .env file
ENTRYPOINT ["node", "apps/api/dist/index.js"]
