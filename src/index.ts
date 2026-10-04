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
  },
  maxHttpBufferSize: 10 * 1024 * 1024 // Allow up to 10MB payloads for image uploads
});

// Middleware
app.use(helmet());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' })); // Support base64 image payloads in JSON
app.use(cookieParser());

// --- Zod Validation Schemas ---
const SignupSchema = z.object({
  villainName: z.string().min(1, "Villain name is required"),
  username: z.string().min(1, "Username is required"),
  email: z.string().email("Invalid email address"),
  password: z.string().min(6, "Password must be at least 6 characters"),
  villainClass: z.nativeEnum(VillainClass).optional().default(VillainClass.MAD_SCIENTIST),
  lairLocation: z.string().min(1, "Lair location is required")
});

const LoginSchema = z.object({
  identifier: z.string(),
  password: z.string()
});

const BountySchema = z.object({
  title: z.string().min(3),
  target: z.string().min(2),
  description: z.string().min(5),
  reward: z.string().min(2),
  creatorId: z.string()
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

// 3. Get All Valid Users (for scrollable dropdown chat selector)
app.get('/api/users', async (req: Request, res: Response) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        username: true,
        villainName: true,
        villainClass: true,
        lairLocation: true,
        avatarUrl: true
      },
      orderBy: { villainName: 'asc' }
    });
    res.json(users);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 4. Get Posts Feed (Global Threat Feed / Scheme Feed)
app.get('/api/posts', async (req: Request, res: Response) => {
  try {
    const posts = await prisma.post.findMany({
      include: { author: { select: { villainName: true, username: true, villainClass: true, avatarUrl: true } } },
      orderBy: { createdAt: 'desc' }
    });
    res.json(posts);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 5. Hero Sightings Feed
app.get('/api/sightings', async (req: Request, res: Response) => {
  try {
    const sightings = await prisma.heroSighting.findMany({
      orderBy: { createdAt: 'desc' }
    });
    res.json(sightings);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 6. Direct Message History Between Two Users
app.get('/api/messages/:user1/:user2', async (req: Request, res: Response) => {
  try {
    const { user1, user2 } = req.params;
    const messages = await prisma.message.findMany({
      where: {
        OR: [
          { senderId: user1, recipientId: user2 },
          { senderId: user2, recipientId: user1 }
        ]
      },
      orderBy: { createdAt: 'asc' }
    });
    res.json(messages);
  } catch (err: any) {
    res.status(500).json({ error: err.message });
  }
});

// 7. Bounty Board Endpoints
app.get('/api/bounties', async (req: Request, res: Response) => {
  try {
    const bounties = await prisma.bounty.findMany({
      include: { creator: { select: { villainName: true, username: true } } },
      orderBy: { createdAt: 'desc' }
    });
    res.json(bounties);
  } catch (err: any) {
    res.json([]);
  }
});

app.post('/api/bounties', async (req: Request, res: Response) => {
  try {
    const data = BountySchema.parse(req.body);
    const bounty = await prisma.bounty.create({
      data: {
        title: data.title,
        target: data.target,
        description: data.description,
        reward: data.reward,
        creatorId: data.creatorId
      }
    });
    io.emit('new_bounty_posted', bounty);
    return res.status(201).json(bounty);
  } catch (err: any) {
    return res.status(400).json({ error: err.errors || err.message });
  }
});

// --- Real-Time Socket.IO Engine ---
io.on('connection', (socket) => {
  console.log(`[SOCKET CONNECTED]: ${socket.id}`);

  socket.on('join_user_room', (userId: string) => {
    socket.join(userId);
  });

  socket.on('report_hero_sighting', async (data) => {
    try {
      const { reporterId, heroName, location, dangerLevel } = data;
      const sighting = await prisma.heroSighting.create({
        data: { reporterId, heroName, location, dangerLevel: Number(dangerLevel) }
      });
      io.emit('global_hero_alert', sighting);
    } catch (err) {
      console.error("Error saving hero sighting:", err);
    }
  });

  socket.on('send_direct_message', async (data) => {
    try {
      const { senderId, recipientId, content, imageUrl } = data;

      const message = await prisma.message.create({
        data: { senderId, recipientId, content: content || '', imageUrl: imageUrl || null }
      });

      io.to(recipientId).emit('receive_direct_message', message);
      io.to(senderId).emit('receive_direct_message', message);
    } catch (err) {
      console.error("Error sending direct message:", err);
    }
  });

  socket.on('disconnect', () => {
    console.log(`[SOCKET DISCONNECTED]: ${socket.id}`);
  });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Doomstack API running on port ${PORT} [Node.js + Postgres]`);
});