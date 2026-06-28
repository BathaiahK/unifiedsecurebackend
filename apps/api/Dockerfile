FROM node:20-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache openssl libc6-compat

# Install pnpm
RUN npm install -g pnpm

# Copy entire workspace
COPY . .

# Install all dependencies (including dev dependencies for tsx)
RUN CI=true pnpm install --frozen-lockfile

# CRITICAL: Remove nested node_modules that block workspace resolution
# pnpm creates nested node_modules in each package, but they interfere with
# finding workspace packages in /app/node_modules. Keep ONLY root /app/node_modules.
RUN find /app -type d -name 'node_modules' ! -path '/app/node_modules' ! -path '/app/node_modules/*' -exec rm -rf {} + 2>/dev/null || true

# Generate Prisma client
RUN pnpm db:generate

# Run the API directly from source using tsx
# This avoids all module resolution issues with built code
EXPOSE 4000

# Use tsx directly from node_modules to run TypeScript source
CMD ["/app/node_modules/.pnpm/node_modules/.bin/tsx", "apps/api/src/index.ts"]
