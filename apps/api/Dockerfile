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

# Generate Prisma client
RUN pnpm db:generate

# Run the API directly from source using tsx
# This avoids all module resolution issues with built code
EXPOSE 4000

CMD ["pnpm", "exec", "tsx", "--env-file=.env", "apps/api/src/index.ts"]
