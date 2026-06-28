FROM node:20-alpine

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache openssl libc6-compat

# Install pnpm
RUN npm install -g pnpm

# Copy workspace files
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY packages ./packages
COPY apps/api ./apps/api

# Install dependencies (pnpm preserves symlinks better in single stage)
RUN CI=true pnpm install --frozen-lockfile

# Generate Prisma client
RUN pnpm db:generate

# Build the project
RUN pnpm -r build

# Remove dev dependencies to slim the image
RUN pnpm prune --prod

# Expose port
EXPOSE 4000

# Start the API
ENTRYPOINT ["node", "apps/api/dist/index.js"]
