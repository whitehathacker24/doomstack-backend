import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';

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

// ==================== AUTH HELPERS ====================
const JWT_SECRET = process.env.JWT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') throw new Error('JWT_SECRET must be set in production');
  return 'dev-only-secret';
})();
const sign = (id: string) => jwt.sign({ id }, JWT_SECRET, { expiresIn: '7d' });
const bump = (id: string, n: number) => prisma.user.update({ where: { id }, data: { notoriety: { increment: n } } }).catch(() => {});
const notify = async (userId: string, type: string, text: string) => {
  try { const n = await prisma.notification.create({ data: { userId, type, text } }); io.to(userId).emit('notification', n); } catch { /* best effort */ }
};
const muted = async (id: string) => {
  const u = await prisma.user.findUnique({ where: { id }, select: { mutedUntil: true } });
  return !!u?.mutedUntil && u.mutedUntil > new Date();
};
const auth: express.RequestHandler = async (req, res, next) => {
  try {
    const t = (req.headers.authorization || '').replace('Bearer ', '');
    const { id } = jwt.verify(t, JWT_SECRET) as { id: string };
    const u = await prisma.user.findUnique({ where: { id } });
    if (!u || u.banned) return res.status(401).json({ error: 'Unauthorized' });
    (req as any).user = u;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
};
const adminOnly: express.RequestHandler = (req, res, next) =>
  (req as any).user.role === 'ADMIN' ? next() : res.status(403).json({ error: 'Admins only' });

io.use(async (socket, next) => {
  try {
    const { id } = jwt.verify(String(socket.handshake.auth?.token || ''), JWT_SECRET) as { id: string };
    const u = await prisma.user.findUnique({ where: { id }, select: { id: true, banned: true } });
    if (!u || u.banned) return next(new Error('unauthorized'));
    socket.data.userId = u.id;
    next();
  } catch { next(new Error('unauthorized')); }
});
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
    res.status(201).json({ user: safe, token: sign(user.id) });
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
    res.json({ user: safe, token: sign(user.id) });
  } catch (err) { console.error('Login error:', err); res.status(500).json({ error: 'Internal server error during authentication' }); }
});

// Everything below /api requires a valid token; identity fields are forced to the caller
app.use('/api', auth);
app.use('/api', (req, res, next) => {
  const me = (req as any).user;
  if (req.method !== 'GET' && me.mutedUntil && me.mutedUntil > new Date() && !req.path.startsWith('/admin'))
    return res.status(403).json({ error: 'You are muted' });
  if (req.body && typeof req.body === 'object')
    for (const k of ['authorId', 'userId', 'creatorId']) if (k in req.body) req.body[k] = me.id;
  next();
});
const selfOnly = (p: string) => app.use(p, (req, res, next) =>
  Object.values(req.params)[0] === (req as any).user.id ? next() : res.status(403).json({ error: 'Forbidden' }));
selfOnly('/api/users/:id'); selfOnly('/api/messages/:userA'); selfOnly('/api/unread/:userId');

app.get('/api/me', (req, res) => { const { passwordHash: _, ...u } = (req as any).user; res.json({ user: u }); });

// ==================== PROFILES ====================
app.get('/api/users', async (_req, res) => {
  try { res.json(await prisma.user.findMany({ where: { banned: false }, select: publicUser })); }
  catch { res.status(500).json({ error: 'Failed to retrieve villain directory' }); }
});

const profileSchema = z.object({
  villainName: z.string().min(1).max(60).optional(),
  headline: z.string().max(120).optional(),
  catchphrase: z.string().max(120).optional(),
  nemesis: z.string().max(60).optional(),
  evilCv: z.string().max(2000).optional(),
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
      where: { AND: [{ OR: [{ senderId: userA, recipientId: userB }, { senderId: userB, recipientId: userA }] }, { OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }] },
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
app.get('/api/posts', async (req, res) => {
  try {
    const tag = String(req.query.tag || '').replace(/[^a-zA-Z0-9_]/g, '');
    res.json(await prisma.post.findMany({
      where: tag ? { content: { contains: '#' + tag, mode: 'insensitive' } } : undefined,
      orderBy: { createdAt: 'desc' }, take: 50,
      include: {
        author: { select: { id: true, villainName: true, username: true } },
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
    bump(p.data.authorId, 5);
    const names = [...new Set((p.data.content.match(/@([a-zA-Z0-9_]{2,30})/g) || []).map(m => m.slice(1)))];
    if (names.length) {
      const us = await prisma.user.findMany({ where: { username: { in: names } }, select: { id: true } });
      us.forEach(u => u.id !== p.data.authorId && notify(u.id, 'mention', `${(req as any).user.villainName} mentioned you in a post`));
    }
    io.emit('new_post', post);
    res.status(201).json(post);
  } catch { res.status(500).json({ error: 'Failed to publish scheme' }); }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const key = { postId_userId: { postId: req.params.id, userId: String(req.body.userId) } };
    const existing = await prisma.like.findUnique({ where: key });
    if (existing) await prisma.like.delete({ where: key });
    else {
      const l = await prisma.like.create({ data: { postId: req.params.id, userId: String(req.body.userId) }, include: { post: { select: { authorId: true } } } });
      if (l.post.authorId !== l.userId) notify(l.post.authorId, 'like', `${(req as any).user.villainName} gave your post an Evil Nod`);
    }
    res.json({ liked: !existing });
  } catch { res.status(500).json({ error: 'Failed to toggle like' }); }
});

app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    const c = z.object({ authorId: z.string(), content: z.string().min(1).max(500) }).safeParse(req.body);
    if (!c.success) return bad(res, c.error.flatten());
    const cm = await prisma.comment.create({ data: { ...c.data, postId: req.params.id }, include: { post: { select: { authorId: true } } } });
    if (cm.post.authorId !== cm.authorId) notify(cm.post.authorId, 'comment', `${(req as any).user.villainName} commented on your post`);
    res.status(201).json(cm);
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
      expiresAt: z.string().optional(),
      rewardCoins: z.number().int().min(0).max(1000000).optional()
    }).safeParse(req.body);
    if (!p.success) return bad(res, 'Missing or invalid contract parameters');
    const { expiresAt, description, category, rewardCoins, ...rest } = p.data;
    const coins = rewardCoins || 0;
    const bounty = await prisma.$transaction(async tx => {
      if (coins) {
        const r = await tx.user.updateMany({ where: { id: rest.creatorId, coins: { gte: coins } }, data: { coins: { decrement: coins } } });
        if (!r.count) throw new Error('INSUFFICIENT');
      }
      return tx.bounty.create({
        data: { ...rest, rewardCoins: coins, description: description || '', category: category || 'GENERAL', expiresAt: expiresAt ? new Date(expiresAt) : null }
      });
    });
    io.emit('new_bounty_posted', bounty);
    res.status(201).json(bounty);
  } catch (err) { if ((err as Error).message === 'INSUFFICIENT') return bad(res, 'Not enough Doom Coins for that escrow'); console.error('Post bounty error:', err); res.status(500).json({ error: 'Failed to publish bounty contract' }); }
});

app.post('/api/bounties/:id/claim', async (req, res) => {
  try {
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.status !== 'OPEN' || b.creatorId === req.body.userId || (b.expiresAt && b.expiresAt < new Date())) return bad(res, 'Contract unavailable');
    const u = await prisma.bounty.update({ where: { id: b.id }, data: { status: 'IN_PROGRESS', claimerId: String(req.body.userId) } });
    notify(b.creatorId, 'bounty', `${(req as any).user.villainName} claimed your contract "${b.title}"`);
    io.emit('new_bounty_posted', u);
    res.json(u);
  } catch { res.status(500).json({ error: 'Failed to claim contract' }); }
});

app.post('/api/bounties/:id/complete', async (req, res) => {
  try {
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.creatorId !== req.body.userId) return res.status(403).json({ error: 'Only the creator can complete it' });
    if (b.status !== 'IN_PROGRESS' || !b.claimerId) return bad(res, 'Contract is not in progress');
    const u = await prisma.$transaction(async tx => {
      await tx.user.update({ where: { id: b.claimerId! }, data: { coins: { increment: b.rewardCoins }, notoriety: { increment: 10 } } });
      notify(b.claimerId!, 'bounty', `Contract "${b.title}" completed${b.rewardCoins ? ` — you were paid ${b.rewardCoins} 🪙` : ''}`);
      return tx.bounty.update({ where: { id: b.id }, data: { status: 'COMPLETED' } });
    });
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

// ==================== ECONOMY, INTEL, SEARCH ====================
app.post('/api/bounties/:id/cancel', async (req, res) => {
  try {
    const me = (req as any).user;
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.creatorId !== me.id || b.status !== 'OPEN') return bad(res, 'Cannot cancel this contract');
    await prisma.$transaction([
      prisma.user.update({ where: { id: me.id }, data: { coins: { increment: b.rewardCoins } } }),
      prisma.bounty.delete({ where: { id: b.id } })
    ]);
    io.emit('new_bounty_posted', { id: b.id });
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Failed to cancel contract' }); }
});

app.get('/api/leaderboard', async (_req, res) => {
  res.json(await prisma.user.findMany({ where: { banned: false }, orderBy: { coins: 'desc' }, take: 10, select: { villainName: true, username: true, coins: true, notoriety: true } }));
});

app.get('/api/heroes', async (_req, res) => {
  res.json(await prisma.heroSighting.groupBy({ by: ['heroName'], _count: true, _max: { dangerLevel: true, createdAt: true }, orderBy: { _count: { heroName: 'desc' } }, take: 30 }));
});

app.get('/api/messages/:userA/:userB/search', async (req, res) => {
  const { userA, userB } = req.params;
  const q = String(req.query.q || '').slice(0, 100);
  res.json(await prisma.message.findMany({
    where: { content: { contains: q, mode: 'insensitive' }, OR: [{ senderId: userA, recipientId: userB }, { senderId: userB, recipientId: userA }] },
    orderBy: { createdAt: 'asc' }, take: 100
  }));
});

app.delete('/api/posts/:id', async (req, res) => {
  const me = (req as any).user;
  const p = await prisma.post.findUnique({ where: { id: req.params.id } });
  if (!p || (p.authorId !== me.id && me.role !== 'ADMIN')) return res.status(403).json({ error: 'Forbidden' });
  await prisma.post.delete({ where: { id: p.id } });
  io.emit('new_post', { id: p.id });
  res.json({ ok: true });
});

// ==================== ADMIN ====================
app.post('/api/admin/users/:id/ban', adminOnly, async (req, res) => {
  const banned = !!req.body.banned;
  await prisma.user.update({ where: { id: req.params.id }, data: { banned } });
  if (banned) io.in(req.params.id).disconnectSockets(true);
  res.json({ ok: true });
});
app.post('/api/admin/users/:id/mute', adminOnly, async (req, res) => {
  const minutes = Math.max(0, Math.min(Number(req.body.minutes) || 0, 60 * 24 * 30));
  await prisma.user.update({ where: { id: req.params.id }, data: { mutedUntil: minutes ? new Date(Date.now() + minutes * 60_000) : null } });
  res.json({ ok: true });
});

// ==================== SOCIAL ====================
const SKILLS = ['Mind Control', 'Explosives', 'Hacking', 'Henchman Management', 'Doomsday Devices', 'Evil Laughter'];

app.get('/api/profile/:id', async (req, res) => {
  const me = (req as any).user.id;
  const u = await prisma.user.findUnique({ where: { id: req.params.id }, select: { ...publicUser, evilCv: true, notoriety: true, createdAt: true } });
  if (!u) return res.status(404).json({ error: 'Villain not found' });
  const [followers, following, isF, endorsements] = await Promise.all([
    prisma.follow.count({ where: { followedId: u.id } }),
    prisma.follow.count({ where: { followerId: u.id } }),
    prisma.follow.findUnique({ where: { followerId_followedId: { followerId: me, followedId: u.id } } }),
    prisma.endorsement.groupBy({ by: ['skill'], where: { endorsedId: u.id }, _count: true })
  ]);
  res.json({ user: u, followers, following, isFollowing: !!isF, endorsements });
});

app.post('/api/follow/:targetId', async (req, res) => {
  const me = (req as any).user, t = req.params.targetId;
  if (t === me.id) return bad(res, 'You cannot follow yourself');
  const key = { followerId_followedId: { followerId: me.id, followedId: t } };
  const ex = await prisma.follow.findUnique({ where: key });
  if (ex) await prisma.follow.delete({ where: key });
  else { await prisma.follow.create({ data: { followerId: me.id, followedId: t } }); notify(t, 'follow', `${me.villainName} is now following you`); }
  res.json({ following: !ex });
});

app.post('/api/endorse/:targetId', async (req, res) => {
  const me = (req as any).user, t = req.params.targetId, skill = String(req.body.skill);
  if (t === me.id || !SKILLS.includes(skill)) return bad(res, 'Invalid endorsement');
  await prisma.endorsement.upsert({
    where: { endorserId_endorsedId_skill: { endorserId: me.id, endorsedId: t, skill } }, update: {},
    create: { endorserId: me.id, endorsedId: t, skill }
  });
  notify(t, 'endorse', `${me.villainName} endorsed you for ${skill}`);
  res.json({ ok: true });
});

app.get('/api/notifications', async (req, res) => {
  const me = (req as any).user.id;
  const [items, unread] = await Promise.all([
    prisma.notification.findMany({ where: { userId: me }, orderBy: { createdAt: 'desc' }, take: 30 }),
    prisma.notification.count({ where: { userId: me, read: false } })
  ]);
  res.json({ items, unread });
});
app.post('/api/notifications/read', async (req, res) => {
  await prisma.notification.updateMany({ where: { userId: (req as any).user.id, read: false }, data: { read: true } });
  res.json({ ok: true });
});

app.get('/api/trending', async (_req, res) => {
  const ps = await prisma.post.findMany({ orderBy: { createdAt: 'desc' }, take: 200, select: { content: true } });
  const c: Record<string, number> = {};
  ps.forEach(p => (p.content.match(/#[a-zA-Z0-9_]{2,30}/g) || []).forEach(t => { const k = t.slice(1).toLowerCase(); c[k] = (c[k] || 0) + 1; }));
  res.json(Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 8));
});

// ==================== SECRET SOCIETIES ====================
const isMember = (societyId: string, userId: string) =>
  prisma.societyMember.findUnique({ where: { societyId_userId: { societyId, userId } } });

app.get('/api/societies', async (req, res) => {
  const ms = await prisma.societyMember.findMany({ where: { userId: (req as any).user.id }, include: { society: true } });
  res.json(ms.map(m => m.society));
});
app.post('/api/societies', async (req, res) => {
  const p = z.object({ name: z.string().min(2).max(50) }).safeParse(req.body);
  if (!p.success) return bad(res, 'Society name must be 2-50 characters');
  const me = (req as any).user.id;
  const s = await prisma.society.create({ data: { name: p.data.name, inviteCode: randomBytes(4).toString('hex'), members: { create: { userId: me } } } });
  io.in(me).socketsJoin('soc:' + s.id);
  res.status(201).json(s);
});
app.post('/api/societies/join', async (req, res) => {
  const me = (req as any).user.id;
  const s = await prisma.society.findUnique({ where: { inviteCode: String(req.body.code || '').trim() } });
  if (!s) return bad(res, 'Invalid invite code');
  await prisma.societyMember.upsert({ where: { societyId_userId: { societyId: s.id, userId: me } }, update: {}, create: { societyId: s.id, userId: me } });
  io.in(me).socketsJoin('soc:' + s.id);
  res.json(s);
});
app.get('/api/societies/:id/messages', async (req, res) => {
  if (!(await isMember(req.params.id, (req as any).user.id))) return res.status(403).json({ error: 'Members only' });
  res.json(await prisma.societyMessage.findMany({ where: { societyId: req.params.id }, orderBy: { createdAt: 'asc' }, take: 200, include: { sender: { select: { villainName: true } } } }));
});

// ==================== SOCKET.IO ====================
io.on('connection', (socket) => {
  console.log(`[CLIENT CONNECTED]: ${socket.id}`);

  // Identity comes from the verified token, never from the client payload
  socket.use((packet, next) => {
    const p = packet[1];
    if (p && typeof p === 'object' && !Array.isArray(p))
      for (const k of ['senderId', 'readerId', 'userId', 'reporterId', 'from']) if (k in p) p[k] = socket.data.userId;
    next();
  });
  prisma.societyMember.findMany({ where: { userId: socket.data.userId } })
    .then(ms => ms.forEach(m => socket.join('soc:' + m.societyId))).catch(() => {});

  socket.on('join_user_room', (userId) => {
    socket.join(String(socket.data.userId));
  });

  socket.on('send_direct_message', async (data) => {
    try {
      const { senderId, recipientId, content, imageUrl, replyToId, ttl } = data || {};
      if (!senderId || !recipientId) return;
      if (String(content || '').length > 2000 || (await muted(senderId))) return;
      const message = await prisma.message.create({
        data: {
          senderId, recipientId, content: content || '', imageUrl: imageUrl || null, replyToId: replyToId || null,
          expiresAt: Number(ttl) > 0 ? new Date(Date.now() + Math.min(Number(ttl), 86400) * 1000) : null
        }
      });
      bump(senderId, 1);
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
      bump(reporterId, 2);
    } catch (err) { console.error('Error reporting hero sighting:', err); }
  });

  socket.on('pin_message', async ({ messageId, userId }) => {
    try {
      const m = await prisma.message.findUnique({ where: { id: messageId } });
      if (!m || (m.senderId !== userId && m.recipientId !== userId)) return;
      const u = await prisma.message.update({ where: { id: messageId }, data: { pinned: !m.pinned } });
      io.to(m.senderId).to(m.recipientId).emit('message_updated', u);
    } catch (err) { console.error('pin_message error:', err); }
  });

  socket.on('edit_message', async ({ messageId, userId, content }) => {
    try {
      const m = await prisma.message.findUnique({ where: { id: messageId } });
      if (!m || m.senderId !== userId || !String(content || '').trim() || String(content).length > 2000) return;
      const u = await prisma.message.update({ where: { id: messageId }, data: { content, editedAt: new Date() } });
      io.to(m.senderId).to(m.recipientId).emit('message_updated', u);
    } catch (err) { console.error('edit_message error:', err); }
  });

  socket.on('send_society_message', async ({ societyId, content }) => {
    try {
      const me = socket.data.userId as string;
      if (!content || String(content).length > 2000 || (await muted(me)) || !(await isMember(societyId, me))) return;
      const m = await prisma.societyMessage.create({ data: { societyId, senderId: me, content }, include: { sender: { select: { villainName: true } } } });
      bump(me, 1);
      io.to('soc:' + societyId).emit('society_message', m);
    } catch (err) { console.error('society message error:', err); }
  });

  socket.on('disconnect', () => console.log(`[CLIENT DISCONNECTED]: ${socket.id}`));
});

setInterval(() => prisma.message.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => {}), 30_000);

if (process.env.ADMIN_USERNAME)
  prisma.user.updateMany({ where: { username: process.env.ADMIN_USERNAME }, data: { role: 'ADMIN' } }).catch(console.error);

server.listen(PORT, () => console.log(`DOOMSTACK backend server running on port ${PORT}`));