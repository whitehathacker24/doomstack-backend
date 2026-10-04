FROM node:18-bullseye-slim

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
CMD ["sh", "-c", "npx prisma db push && node dist/index.js"]