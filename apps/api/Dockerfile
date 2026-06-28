# Build stage
FROM node:20-alpine AS builder

WORKDIR /app

# Copy workspace files
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/api ./apps/api

# Install pnpm and dependencies
RUN npm install -g pnpm && CI=true pnpm install --frozen-lockfile

# Generate Prisma client and build all packages
RUN CI=true pnpm db:generate && pnpm -r build

# Runtime stage
FROM node:20-alpine

WORKDIR /app

# Install system dependencies only
RUN apk add --no-cache openssl libc6-compat

# Copy workspace configuration
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

# Copy built artifacts and ALL node_modules from builder
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/apps/api/dist ./apps/api/dist
COPY --from=builder /app/packages ./packages

# Expose port
EXPOSE 4000

# Start the API
ENTRYPOINT ["node", "apps/api/dist/index.js"]
