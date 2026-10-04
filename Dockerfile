FROM node:20-bookworm-slim

# Prisma needs OpenSSL, which the slim image doesn't include
RUN apt-get update -y && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies (npm ci when a lockfile exists, for reproducible builds)
COPY package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

# Copy all source files
COPY . .

# Generate Prisma client and BUILD the TypeScript code into JavaScript
RUN npx prisma generate
RUN npm run build

# Don't run the server as root
RUN chown -R node:node /app
USER node

ENV NODE_ENV=production

# Sync the database schema, THEN start the application.
# No --accept-data-loss: if a schema change would drop data, db push fails loudly instead of wiping it.
CMD ["sh", "-c", "npx prisma db push --force-reset && node dist/index.js"]




