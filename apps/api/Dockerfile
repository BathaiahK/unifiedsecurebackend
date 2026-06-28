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

# Set NODE_PATH to prioritize workspace packages in root node_modules
# This ensures @usp/config resolves from /app/node_modules not /app/apps/api/node_modules
ENV NODE_PATH=/app/node_modules

# Run from /app root with tsx to execute TypeScript source
WORKDIR /app
CMD ["/app/node_modules/.pnpm/node_modules/.bin/tsx", "apps/api/src/index.ts"]
