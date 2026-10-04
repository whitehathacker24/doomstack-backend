FROM node:18-bullseye-slim

WORKDIR /app

# Install OpenSSL and other necessary dependencies for Prisma
RUN apt-get update -y && apt-get install -y openssl python3 make g++

# Copy package files and install dependencies
COPY package*.json ./
RUN npm install

# Copy the rest of your app source code including prisma folder
COPY . .

# Generate Prisma client
RUN npx prisma generate

# Expose the port your app runs on
EXPOSE 5000

# Automatically push/deploy database tables on startup, then start the server
CMD ["sh", "-c", "npx prisma db push && npm start"]