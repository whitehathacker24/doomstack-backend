FROM node:20-bookworm-slim

# Prisma needs OpenSSL, which the slim image doesn't include
RUN apt-get update -y && apt-get install -y --no-install-recommends openssl ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm install

# Copy all source files
COPY . .

# Generate Prisma client and BUILD the TypeScript code into JavaScript
RUN npx prisma generate
RUN npm run build

# Push the database schema, THEN start the application
CMD ["sh", "-c", "npx prisma db push --accept-data-loss && node dist/index.js"]