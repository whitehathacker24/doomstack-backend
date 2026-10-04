import express, { Request, Response } from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { PrismaClient, VillainClass } from '@prisma/client';
import { z } from 'zod';

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: true,
    credentials: true
  }
});

// Middleware
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// --- Zod Validation Schemas ---
const SignupSchema = z.object({
  villainName: z.string().min(2),
  username: z.string().min(3),
  email: z.string().email(),
  password: z.string().min(8),
  villainClass: z.nativeEnum(VillainClass),
  lairLocation: z.string().min(2)
});

const LoginSchema = z.object({
  identifier: z.string(),
  password: z.string()
});

// --- REST Endpoints ---

// 1. User Signup
app.post('/api/auth/signup', async (req: Request, res: Response) => {
  try {
    const data = SignupSchema.parse(req.body);
    const existing = await prisma.user.findFirst({
      where: { OR: [{ email: data.email }, { username: data.username }] }
    });

    if (existing) {
      return res.status(400).json({ error: "Username or email already registered." });
    }

    const passwordHash = await bcrypt.hash(data.password, 12);
    const user = await prisma.user.create({
      data: {
        villainName: data.villainName,
        username: data.username,
        email: data.email,
        passwordHash,
        villainClass: data.villainClass,
        lairLocation: data.lairLocation,
        headline: `${data.villainClass} based out of ${data.lairLocation}`
      }
    });

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 });

    return res.status(201).json({ user: { id: user.id, username: user.username, villainName: user.villainName } });
  } catch (err: any) {
    return res.status(400).json({ error: err.errors || err.message });
  }
});

// 2. User Login
app.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const data = LoginSchema.parse(req.body);
    const user = await prisma.user.findFirst({
      where: { OR: [{ email: data.identifier }, { username: data.identifier }] }
    });

    if (!user || !(await bcrypt.compare(data.password, user.passwordHash))) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET!, { expiresIn: '7d' });
    res.cookie('token', token, { httpOnly: true, maxAge: 7 * 24 * 3600 * 1000 });

    return res.json({ user: { id: user.id, username: user.username, villainName: user.villainName } });
  } catch (err: any) {
    return res.status(400).json({ error: err.errors || err.message });
  }
});

// 3. Get Posts Feed
app.get('/api/posts', async (req: Request, res: Response) => {
  const posts = await prisma.post.findMany({
    include: { author: { select: { villainName: true, username: true, villainClass: true, avatarUrl: true } } },
    orderBy: { createdAt: 'desc' }
  });
  res.json(posts);
});

// --- Real-Time Socket.IO Engine ---
io.on('connection', (socket) => {
  console.log(`[SOCKET CONNECTED]: ${socket.id}`);

  // Join Personal Room for Direct Messages
  socket.on('join_user_room', (userId: string) => {
    socket.join(userId);
  });

  // Real-time Hero Alert Broadcast
  socket.on('report_hero_sighting', async (data) => {
    const { reporterId, heroName, location, dangerLevel } = data;
    
    // Save sighting to Postgres
    const sighting = await prisma.heroSighting.create({
      data: { reporterId, heroName, location, dangerLevel: Number(dangerLevel) }
    });

    // Broadcast emergency alert to all connected sockets
    io.emit('global_hero_alert', sighting);
  });

  // Direct Encrypted Messaging
  socket.on('send_direct_message', async (data) => {
    const { senderId, recipientId, content } = data;

    const message = await prisma.message.create({
      data: { senderId, recipientId, content }
    });

    // Emit to recipient's socket room
    io.to(recipientId).emit('receive_direct_message', message);
  });

  socket.on('disconnect', () => {
    console.log(`[SOCKET DISCONNECTED]: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Doomstack API running on port ${PORT} [Node.js + Postgres]`);
});