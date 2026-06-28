FROM node:20-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache openssl libc6-compat

# Install pnpm
RUN npm install -g pnpm

# Copy everything
COPY . .

# Install dependencies
RUN CI=true pnpm install --frozen-lockfile

# Generate Prisma client and build
RUN pnpm db:generate
RUN pnpm -r build

# Remove nested node_modules that interfere with module resolution
# Keep only root /app/node_modules for workspace symlinks
RUN find /app -path '*/node_modules' -not -path '/app/node_modules' -not -path '/app/node_modules/*' -type d -exec rm -rf {} + 2>/dev/null || true

# Expose port
EXPOSE 4000

# Run the API from the workspace root to resolve workspace packages
WORKDIR /app
CMD ["node", "apps/api/dist/index.js"]
