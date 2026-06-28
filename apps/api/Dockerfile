FROM node:20-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache openssl libc6-compat

# Install pnpm
RUN npm install -g pnpm

# Copy entire workspace
COPY . .

# Install all dependencies
RUN CI=true pnpm install --frozen-lockfile

# Generate Prisma client (needs nested node_modules)
RUN pnpm db:generate

# Fix module resolution: create symlinks in nested @usp directories
# pointing to the root workspace packages
RUN for pkg in /app/node_modules/@usp/*; do \
    pkgname=$(basename "$pkg"); \
    if [ -d "/app/apps/api/node_modules/@usp/$pkgname" ]; then \
      rm -rf "/app/apps/api/node_modules/@usp/$pkgname"; \
    fi; \
    ln -s "$pkg" "/app/apps/api/node_modules/@usp/$pkgname"; \
  done

# Expose port
EXPOSE 4000

# Run from /app root with tsx to execute TypeScript source
WORKDIR /app
CMD ["/app/node_modules/.pnpm/node_modules/.bin/tsx", "apps/api/src/index.ts"]
