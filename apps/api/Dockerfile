FROM node:20-alpine

WORKDIR /app

# Install required system dependencies for Prisma
RUN apk add --no-cache openssl libc6-compat

# Install pnpm
RUN npm install -g pnpm

# Copy everything
COPY . .

# Install all dependencies
RUN CI=true pnpm install

# Generate Prisma client
RUN pnpm db:generate

# Build the project
RUN pnpm -r build

# Expose port
EXPOSE 4000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:4000/health || exit 1

# Run API
CMD ["node", "apps/api/dist/index.js"]
