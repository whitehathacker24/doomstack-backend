FROM node:18-bullseye-slim

WORKDIR /app

# Use Debian archive mirrors for older bullseye-slim builds to avoid 404 package errors
RUN sed -i 's/deb.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i 's/security.debian.org/archive.debian.org/g' /etc/apt/sources.list && \
    sed -i '/buster-updates/d' /etc/apt/sources.list || true

# Install OpenSSL and necessary dependencies
RUN apt-get update -y && apt-get install -y --allow-unauthenticated openssl python3 make g++

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy source code
COPY . .

# Generate Prisma client
RUN npx prisma generate

EXPOSE 5000

CMD ["sh", "-c", "npx prisma db push && npm start"]