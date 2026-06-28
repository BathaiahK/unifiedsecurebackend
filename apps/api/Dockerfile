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

# Expose port
EXPOSE 4000

# Use pnpm to run the API (preserves workspace resolution)
ENTRYPOINT ["pnpm", "--filter", "@usp/api", "start"]
