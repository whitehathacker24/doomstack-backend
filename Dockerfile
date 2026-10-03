# Stage 1: Build the TypeScript code
FROM node:18-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY prisma ./prisma/
COPY . .
RUN npx prisma generate
RUN npm run build

# Stage 2: Run the production server
FROM node:18-alpine AS runner
WORKDIR /app
ENV NODE_ENV=production

# Install OpenSSL so Prisma can communicate with Postgres
RUN apk add --no-cache openssl

COPY package*.json ./
RUN npm install --omit=dev

COPY --from=builder /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=builder /app/dist ./dist

EXPOSE 5000
CMD ["npm", "start"]