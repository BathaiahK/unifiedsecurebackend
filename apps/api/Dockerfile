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

# Expose port
EXPOSE 4000

# Run from /app root with tsx to execute TypeScript source
# Use NODE_OPTIONS to enable better module resolution for workspace packages
WORKDIR /app
ENV NODE_OPTIONS=--experimental-specifier-resolution=node
CMD ["/app/node_modules/.pnpm/node_modules/.bin/tsx", "apps/api/src/index.ts"]
