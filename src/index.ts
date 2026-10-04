import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);

// Configure CORS for Express and Socket.IO
const allowedOrigins = ['*']; // Adjust this if you want to lock it down to your frontend origin

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json({ limit: '10mb' })); // Increased limit to support base64 image attachments

const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = process.env.PORT || 4000;

// ==================== REST API ROUTES ====================

// Health Check
app.get('/', (req, res) => {
  res.send('DOOMSTACK Central Command Backend is operational.');
});

// User Registration (Signup)
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { villainName, username, villainClass, email, password, lairLocation } = req.body;
    
    if (!villainName || !username || !email || !password) {
      return res.status(400).json({ error: 'Missing required credentials' });
    }

    const existingUser = await prisma.user.findFirst({
      where: { OR: [{ email }, { username }] }
    });

    if (existingUser) {
      return res.status(400).json({ error: 'Username or email already registered' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        villainName,
        username,
        villainClass: villainClass || 'HENCHMAN',
        email,
        passwordHash: hashedPassword,
        lairLocation: lairLocation || 'Unknown Lair'
      }
    });

    const { passwordHash: _, ...userWithoutPassword } = newUser;
    res.status(201).json({ user: userWithoutPassword });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;

    if (!identifier || !password) {
      return res.status(400).json({ error: 'Identifier and password are required' });
    }

    const user = await prisma.user.findFirst({
      where: { OR: [{ email: identifier }, { username: identifier }] }
    });

    if (!user) {
      return res.status(404).json({ error: 'Villain profile not found' });
    }

    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Invalid security clearance (password)' });
    }

    const { passwordHash: _, ...userWithoutPassword } = user;
    res.json({ user: userWithoutPassword });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
});

// Get All Users (Directory)
app.get('/api/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        villainName: true,
        username: true,
        villainClass: true,
        lairLocation: true
      }
    });
    res.json(users);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Failed to retrieve villain directory' });
  }
});

// Get Direct Message History between two users
app.get('/api/messages/:userA/:userB', async (req, res) => {
  try {
    const { userA, userB } = req.params;
    const messages = await prisma.message.findMany({
      where: {
        OR: [
          { senderId: userA, recipientId: userB },
          { senderId: userB, recipientId: userA }
        ]
      },
      orderBy: { createdAt: 'asc' }
    });
    res.json(messages);
  } catch (err) {
    console.error('Fetch messages error:', err);
    res.status(500).json({ error: 'Failed to retrieve transmission history' });
  }
});

// Get Bounty Board Contracts
app.get('/api/bounties', async (req, res) => {
  try {
    const bounties = await prisma.bounty.findMany({
      orderBy: { createdAt: 'desc' }
    });
    res.json(bounties);
  } catch (err) {
    console.error('Fetch bounties error:', err);
    res.status(500).json({ error: 'Failed to retrieve bounty contracts' });
  }
});

// Post a New Bounty Contract
app.post('/api/bounties', async (req, res) => {
  try {
    const { title, target, description, reward, creatorId } = req.body;
    if (!title || !target || !reward || !creatorId) {
      return res.status(400).json({ error: 'Missing required contract parameters' });
    }

    const bounty = await prisma.bounty.create({
      data: { title, target, description: description || '', reward, creatorId }
    });

    // Broadcast to all connected clients
    io.emit('new_bounty_posted', bounty);
    res.status(201).json(bounty);
  } catch (err) {
    console.error('Post bounty error:', err);
    res.status(500).json({ error: 'Failed to publish bounty contract' });
  }
});

// Get Global Hero Sightings
app.get('/api/sightings', async (req, res) => {
  try {
    const sightings = await prisma.heroSighting.findMany({
      orderBy: { createdAt: 'desc' },
      take: 50
    });
    res.json(sightings);
  } catch (err) {
    console.error('Fetch sightings error:', err);
    res.status(500).json({ error: 'Failed to fetch threat feed' });
  }
});

// ==================== SOCKET.IO HANDLERS ====================

io.on('connection', (socket) => {
  console.log(`[CLIENT CONNECTED]: ${socket.id}`);

  // Join personal user room for direct messaging targeting
  socket.on('join_user_room', (userId) => {
    if (userId) {
      const roomId = String(userId); // FORCE ID TO BE A STRING
      socket.join(roomId);
      console.log(`[ROOM JOINED]: Socket ${socket.id} joined personal room -> ${roomId}`);
    }
  });

  // Handle Direct Messaging
  socket.on('send_direct_message', async (data) => {
    console.log('[SOCKET MESSAGE RECEIVED]:', data);
    try {
      const { senderId, recipientId, content, imageUrl } = data;
      if (!senderId || !recipientId) {
        console.error('Missing senderId or recipientId in direct message payload.');
        return;
      }

      // Persist to database
      const message = await prisma.message.create({
        data: {
          senderId,
          recipientId,
          content: content || '',
          imageUrl: imageUrl || null
        }
      });

      // Emit to both recipient's room and sender's room USING STRING IDs
      io.to(String(recipientId)).emit('receive_direct_message', message);
      io.to(String(senderId)).emit('receive_direct_message', message);
    } catch (err) {
      console.error('Error processing direct message socket event:', err);
    }
  });

  // Handle Hero Sighting Reports
  socket.on('report_hero_sighting', async (data) => {
    try {
      const { reporterId, heroName, location, dangerLevel } = data;
      if (!heroName || !location || !reporterId) return;

      const sighting = await prisma.heroSighting.create({
        data: {
          reporterId,
          heroName,
          location,
          dangerLevel: parseInt(dangerLevel) || 1
        }
      });

      // Broadcast globally to all connected terminals
      io.emit('global_hero_alert', sighting);
    } catch (err) {
      console.error('Error reporting hero sighting:', err);
    }
  });

  socket.on('disconnect', () => {
    console.log(`[CLIENT DISCONNECTED]: ${socket.id}`);
  });
});

server.listen(PORT, () => {
  console.log(`DOOMSTACK backend server running on port ${PORT}`);
});