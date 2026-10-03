FROM node:18-alpine AS builder

WORKDIR /app

# Copy package management files
COPY package*.json ./
COPY prisma ./prisma/

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Generate Prisma Client and build TypeScript code
RUN npx prisma generate
RUN npm run build

# --- Production Stage ---
FROM node:18-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci --only=production

COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/node_modules/@prisma ./node_modules/@prisma
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/prisma ./prisma

EXPOSE 5000

# Run migrations and start API server
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/index.js"]