import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' })); // base64 image attachments
app.use('/api/', rateLimit({ windowMs: 60_000, max: 200 }));
app.use('/api/auth/', rateLimit({ windowMs: 15 * 60_000, max: 30 }));

const io = new Server(server, {
  cors: { origin: true, methods: ['GET', 'POST'], credentials: true },
  maxHttpBufferSize: 10e6
});

const PORT = process.env.PORT || 4000;
const publicUser = { id: true, villainName: true, username: true, villainClass: true, lairLocation: true, headline: true, catchphrase: true, nemesis: true, status: true, avatarUrl: true } as const;
const bad = (res: express.Response, e: unknown) => res.status(400).json({ error: e });

// ==================== AUTH ====================
app.get('/', (_req, res) => { res.send('DOOMSTACK Central Command Backend is operational.'); });

const signupSchema = z.object({
  villainName: z.string().min(1).max(60),
  username: z.string().min(2).max(30),
  email: z.string().email(),
  password: z.string().min(6).max(100),
  villainClass: z.enum(['HENCHMAN','MASTERMIND','MAD_SCIENTIST','CRIME_LORD','SUPER_VILLAIN','CORRUPT_CEO','MERCENARY','OVERLORD']).optional(),
  lairLocation: z.string().max(100).optional()
});

app.post('/api/auth/signup', async (req, res) => {
  try {
    const p = signupSchema.safeParse(req.body);
    if (!p.success) return bad(res, p.error.issues.map(i => i.message).join(', '));
    const { password, ...d } = p.data;
    const existing = await prisma.user.findFirst({ where: { OR: [{ email: d.email }, { username: d.username }] } });
    if (existing) return bad(res, 'Username or email already registered');
    const user = await prisma.user.create({
      data: { ...d, villainClass: d.villainClass || 'HENCHMAN', lairLocation: d.lairLocation || 'Unknown Lair', passwordHash: await bcrypt.hash(password, 10) }
    });
    const { passwordHash: _, ...safe } = user;
    res.status(201).json({ user: safe });
  } catch (err) { console.error('Signup error:', err); res.status(500).json({ error: 'Internal server error during registration' }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { identifier, password } = req.body;
    if (!identifier || !password) return bad(res, 'Identifier and password are required');
    const user = await prisma.user.findFirst({ where: { OR: [{ email: identifier }, { username: identifier }] } });
    if (!user) return res.status(404).json({ error: 'Villain profile not found' });
    if (!(await bcrypt.compare(password, user.passwordHash))) return res.status(401).json({ error: 'Invalid security clearance (password)' });
    const { passwordHash: _, ...safe } = user;
    res.json({ user: safe });
  } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Internal server error during authentication' }); }
});

// ==================== PROFILES ====================
app.get('/api/users', async (_req, res) => {
  try { res.json(await prisma.user.findMany({ select: publicUser })); }
  catch { res.status(500).json({ error: 'Failed to retrieve villain directory' }); }
});

const profileSchema = z.object({
  villainName: z.string().min(1).max(60).optional(),
  headline: z.string().max(120).optional(),
  catchphrase: z.string().max(120).optional(),
  nemesis: z.string().max(60).optional(),
  lairLocation: z.string().max(100).optional(),
  avatarUrl: z.string().max(2_000_000).optional()
});

app.patch('/api/users/:id', async (req, res) => {
  try {
    const p = profileSchema.safeParse(req.body);
    if (!p.success) return bad(res, p.error.flatten());
    const { passwordHash: _, ...user } = await prisma.user.update({ where: { id: req.params.id }, data: p.data });
    res.json({ user });
  } catch { res.status(500).json({ error: 'Failed to update profile' }); }
});

app.post('/api/users/:id/password', async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const u = await prisma.user.findUnique({ where: { id: req.params.id } });
    if (!u || String(newPassword || '').length < 6 || !(await bcrypt.compare(oldPassword || '', u.passwordHash)))
      return bad(res, 'Invalid password change');
    await prisma.user.update({ where: { id: u.id }, data: { passwordHash: await bcrypt.hash(newPassword, 10) } });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Failed to change password' }); }
});

// ==================== MESSAGES ====================
app.get('/api/messages/:userA/:userB', async (req, res) => {
  try {
    const { userA, userB } = req.params;
    res.json(await prisma.message.findMany({
      where: { OR: [{ senderId: userA, recipientId: userB }, { senderId: userB, recipientId: userA }] },
      orderBy: { createdAt: 'asc' }
    }));
  } catch { res.status(500).json({ error: 'Failed to retrieve transmission history' }); }
});

// Unread counts per sender for a user (directory badges)
app.get('/api/unread/:userId', async (req, res) => {
  try {
    const rows = await prisma.message.groupBy({ by: ['senderId'], where: { recipientId: req.params.userId, readAt: null }, _count: true });
    res.json(Object.fromEntries(rows.map(r => [r.senderId, r._count])));
  } catch { res.status(500).json({ error: 'Failed to count unread' }); }
});

// ==================== FEED ====================
app.get('/api/posts', async (_req, res) => {
  try {
    res.json(await prisma.post.findMany({
      orderBy: { createdAt: 'desc' }, take: 50,
      include: {
        author: { select: { villainName: true, username: true } },
        _count: { select: { likes: true } },
        likes: { select: { userId: true } },
        comments: { include: { author: { select: { villainName: true } } }, orderBy: { createdAt: 'asc' } }
      }
    }));
  } catch { res.status(500).json({ error: 'Failed to load feed' }); }
});

app.post('/api/posts', async (req, res) => {
  try {
    const p = z.object({ authorId: z.string(), content: z.string().min(1).max(1000) }).safeParse(req.body);
    if (!p.success) return bad(res, p.error.flatten());
    const post = await prisma.post.create({ data: p.data });
    io.emit('new_post', post);
    res.status(201).json(post);
  } catch { res.status(500).json({ error: 'Failed to publish scheme' }); }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const key = { postId_userId: { postId: req.params.id, userId: String(req.body.userId) } };
    const existing = await prisma.like.findUnique({ where: key });
    if (existing) await prisma.like.delete({ where: key });
    else await prisma.like.create({ data: { postId: req.params.id, userId: String(req.body.userId) } });
    res.json({ liked: !existing });
  } catch { res.status(500).json({ error: 'Failed to toggle like' }); }
});

app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    const c = z.object({ authorId: z.string(), content: z.string().min(1).max(500) }).safeParse(req.body);
    if (!c.success) return bad(res, c.error.flatten());
    res.status(201).json(await prisma.comment.create({ data: { ...c.data, postId: req.params.id } }));
  } catch { res.status(500).json({ error: 'Failed to comment' }); }
});

// ==================== BOUNTIES ====================
app.get('/api/bounties', async (req, res) => {
  try {
    const category = req.query.category ? String(req.query.category) : undefined;
    res.json(await prisma.bounty.findMany({
      where: category ? { category } : undefined,
      orderBy: { createdAt: 'desc' },
      include: { claimer: { select: { villainName: true } } }
    }));
  } catch { res.status(500).json({ error: 'Failed to retrieve bounty contracts' }); }
});

app.post('/api/bounties', async (req, res) => {
  try {
    const p = z.object({
      title: z.string().min(1).max(100), target: z.string().min(1).max(100),
      description: z.string().max(1000).optional(), reward: z.string().min(1).max(100),
      creatorId: z.string(), category: z.enum(['GENERAL', 'SABOTAGE', 'THEFT', 'RECON']).optional(),
      expiresAt: z.string().optional()
    }).safeParse(req.body);
    if (!p.success) return bad(res, 'Missing or invalid contract parameters');
    const { expiresAt, description, category, ...rest } = p.data;
    const bounty = await prisma.bounty.create({
      data: { ...rest, description: description || '', category: category || 'GENERAL', expiresAt: expiresAt ? new Date(expiresAt) : null }
    });
    io.emit('new_bounty_posted', bounty);
    res.status(201).json(bounty);
  } catch (err) { console.error('Post bounty error:', err); res.status(500).json({ error: 'Failed to publish bounty contract' }); }
});

app.post('/api/bounties/:id/claim', async (req, res) => {
  try {
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.status !== 'OPEN' || (b.expiresAt && b.expiresAt < new Date())) return bad(res, 'Contract unavailable');
    const u = await prisma.bounty.update({ where: { id: b.id }, data: { status: 'IN_PROGRESS', claimerId: String(req.body.userId) } });
    io.emit('new_bounty_posted', u);
    res.json(u);
  } catch { res.status(500).json({ error: 'Failed to claim contract' }); }
});

app.post('/api/bounties/:id/complete', async (req, res) => {
  try {
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.creatorId !== req.body.userId) return res.status(403).json({ error: 'Only the creator can complete it' });
    const u = await prisma.bounty.update({ where: { id: b.id }, data: { status: 'COMPLETED' } });
    io.emit('new_bounty_posted', u);
    res.json(u);
  } catch { res.status(500).json({ error: 'Failed to complete contract' }); }
});

// ==================== SIGHTINGS ====================
app.get('/api/sightings', async (_req, res) => {
  try { res.json(await prisma.heroSighting.findMany({ orderBy: { createdAt: 'desc' }, take: 50 })); }
  catch { res.status(500).json({ error: 'Failed to fetch threat feed' }); }
});

app.post('/api/sightings/:id/verify', async (req, res) => {
  try {
    const s = await prisma.heroSighting.update({
      where: { id: req.params.id },
      data: req.body.confirm ? { confirms: { increment: 1 } } : { falseAlarms: { increment: 1 } }
    });
    io.emit('sighting_updated', s);
    res.json(s);
  } catch { res.status(500).json({ error: 'Failed to verify sighting' }); }
});

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
  console.log(`[CLIENT CONNECTED]: ${socket.id}`);

  socket.on('join_user_room', (userId) => {
    if (userId) socket.join(String(userId));
  });

  socket.on('send_direct_message', async (data) => {
    try {
      const { senderId, recipientId, content, imageUrl } = data || {};
      if (!senderId || !recipientId) return;
      if (String(content || '').length > 2000) return;
      const message = await prisma.message.create({
        data: { senderId, recipientId, content: content || '', imageUrl: imageUrl || null }
      });
      io.to(String(recipientId)).emit('receive_direct_message', message);
      io.to(String(senderId)).emit('receive_direct_message', message);
    } catch (err) { console.error('Error processing direct message:', err); }
  });

  socket.on('typing', ({ from, to, name }) => {
    if (from && to) io.to(String(to)).emit('typing', { from, name });
  });

  socket.on('mark_read', async ({ readerId, otherId }) => {
    try {
      await prisma.message.updateMany({ where: { senderId: otherId, recipientId: readerId, readAt: null }, data: { readAt: new Date() } });
      io.to(String(otherId)).emit('messages_read', { by: readerId });
    } catch (err) { console.error('mark_read error:', err); }
  });

  socket.on('react_message', async ({ messageId, userId, emoji }) => {
    try {
      if (!['😈', '🔥', '💀'].includes(emoji)) return;
      const m = await prisma.message.findUnique({ where: { id: messageId } });
      if (!m) return;
      const r = (m.reactions as Record<string, string[]>) || {};
      const has = r[emoji]?.includes(userId);
      r[emoji] = has ? r[emoji].filter(i => i !== userId) : [...(r[emoji] || []), userId];
      const updated = await prisma.message.update({ where: { id: messageId }, data: { reactions: r } });
      io.to(m.senderId).to(m.recipientId).emit('message_updated', updated);
    } catch (err) { console.error('react_message error:', err); }
  });

  socket.on('delete_message', async ({ messageId, userId }) => {
    try {
      const m = await prisma.message.findUnique({ where: { id: messageId } });
      if (!m || m.senderId !== userId) return;
      await prisma.message.delete({ where: { id: messageId } });
      io.to(m.senderId).to(m.recipientId).emit('message_deleted', { id: messageId });
    } catch (err) { console.error('delete_message error:', err); }
  });

  socket.on('set_status', async ({ userId, status }) => {
    try {
      if (!['online', 'offline', 'plotting'].includes(status)) return;
      await prisma.user.update({ where: { id: userId }, data: { status } });
      io.emit('status_changed', { userId, status });
    } catch (err) { console.error('set_status error:', err); }
  });

  socket.on('report_hero_sighting', async (data) => {
    try {
      const { reporterId, heroName, location, dangerLevel } = data || {};
      if (!heroName || !location || !reporterId) return;
      const sighting = await prisma.heroSighting.create({
        data: { reporterId, heroName: String(heroName).slice(0, 80), location: String(location).slice(0, 120), dangerLevel: parseInt(dangerLevel) || 1 }
      });
      io.emit('global_hero_alert', sighting);
    } catch (err) { console.error('Error reporting hero sighting:', err); }
  });

  socket.on('disconnect', () => console.log(`[CLIENT DISCONNECTED]: ${socket.id}`));
});

server.listen(PORT, () => console.log(`DOOMSTACK backend server running on port ${PORT}`));