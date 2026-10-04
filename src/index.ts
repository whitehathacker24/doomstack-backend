import 'dotenv/config';
import express from 'express';
import http from 'http';
import { Server, Socket } from 'socket.io';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { randomBytes } from 'crypto';

const prisma = new PrismaClient();
const app = express();
const server = http.createServer(app);

// Behind Render's proxy: without this every user shares one IP for rate limiting
app.set('trust proxy', 1);

// CLIENT_URL = comma-separated list of allowed frontend origins. Empty = reflect any origin
// (acceptable because auth is a Bearer token, not cookies, but set it in production).
const ALLOWED_ORIGINS = (process.env.CLIENT_URL || '').split(',').map(s => s.trim()).filter(Boolean);
const corsOrigin: boolean | string[] = ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : true;

app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(cors({ origin: corsOrigin, credentials: false }));
// Limiters run before body parsing so floods are rejected cheaply
// The frontend re-fetches lists whenever a broadcast arrives, so this is generous; messages are JSON so the client can show them
app.use('/api/', rateLimit({ windowMs: 60_000, max: 600, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests. Slow down a little.' } }));
app.use('/api/auth/', rateLimit({ windowMs: 15 * 60_000, max: 30, standardHeaders: true, legacyHeaders: false, message: { error: 'Too many attempts. Try again in a few minutes.' } }));
app.use(express.json({ limit: '3mb' })); // largest REST payload is a 2M-char avatar; chat images travel over the socket

const io = new Server(server, {
  cors: { origin: corsOrigin, methods: ['GET', 'POST'], credentials: false },
  maxHttpBufferSize: 10e6
});

const PORT = process.env.PORT || 4000;

// ==================== AUTH HELPERS ====================
// No hardcoded fallback secret: tokens signed with a known string could be forged by anyone.
const JWT_SECRET: string = process.env.JWT_SECRET || (() => {
  if (process.env.NODE_ENV === 'production') throw new Error('JWT_SECRET must be set in production');
  console.warn('[WARN] JWT_SECRET is not set: using a random secret for this run (logins reset on restart).');
  return randomBytes(32).toString('hex');
})();
const sign = (id: string) => jwt.sign({ id }, JWT_SECRET, { expiresIn: '7d' });
const verifyToken = (t: unknown): string | null => {
  try {
    const p = jwt.verify(String(t || ''), JWT_SECRET, { algorithms: ['HS256'] }) as { id?: unknown };
    return typeof p.id === 'string' ? p.id : null;
  } catch { return null; }
};
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
    const id = verifyToken(t);
    if (!id) return res.status(401).json({ error: 'Unauthorized' });
    const u = await prisma.user.findUnique({ where: { id } });
    if (!u || u.banned) return res.status(401).json({ error: 'Unauthorized' });
    (req as any).user = u;
    next();
  } catch { res.status(401).json({ error: 'Unauthorized' }); }
};
const adminOnly: express.RequestHandler = (req, res, next) =>
  (req as any).user.role === 'ADMIN' ? next() : res.status(403).json({ error: 'Admins only' });

// Express 4 does not catch rejected promises from async handlers; an unhandled rejection
// (e.g. a foreign-key error) would crash the whole process. This forwards them to the error handler.
const ah = (fn: express.RequestHandler): express.RequestHandler => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

io.use(async (socket, next) => {
  try {
    const id = verifyToken(socket.handshake.auth?.token);
    if (!id) return next(new Error('unauthorized'));
    const u = await prisma.user.findUnique({ where: { id }, select: { id: true, banned: true, villainName: true } });
    if (!u || u.banned) return next(new Error('unauthorized'));
    socket.data.userId = u.id;
    socket.data.name = u.villainName;
    next();
  } catch { next(new Error('unauthorized')); }
});
const publicUser = { id: true, villainName: true, username: true, villainClass: true, lairLocation: true, headline: true, catchphrase: true, nemesis: true, status: true, avatarUrl: true } as const;
const { avatarUrl: _omitAvatar, ...directoryUser } = publicUser;
const bad = (res: express.Response, e: unknown) => res.status(400).json({ error: e });

// Only real image data URLs (no quotes or markup possible) or plain https URLs
const IMAGE_RE = /^data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}$/;
const AVATAR_RE = /^(data:image\/(png|jpeg|gif|webp);base64,[A-Za-z0-9+/]+={0,2}|https:\/\/[^\s"'<>\\]+)$/;
const MAX_IMAGE_CHARS = 7_000_000; // ~5 MB of image data, under the 10 MB socket limit

// ==================== AUTH ====================
app.get('/', (_req, res) => { res.send('DOOMSTACK Central Command Backend is operational.'); });

const signupSchema = z.object({
  villainName: z.string().trim().min(1).max(60),
  username: z.string().trim().min(2).max(30).regex(/^[A-Za-z0-9_]+$/, 'Username may only contain letters, numbers and underscores'),
  email: z.string().trim().toLowerCase().email().max(120),
  password: z.string().min(6).max(72),
  villainClass: z.enum(['HENCHMAN','MASTERMIND','MAD_SCIENTIST','CRIME_LORD','SUPER_VILLAIN','CORRUPT_CEO','MERCENARY','OVERLORD']).optional(),
  lairLocation: z.string().trim().max(100).optional()
});
const loginSchema = z.object({ identifier: z.string().trim().min(1).max(120), password: z.string().min(1).max(100) });
// Keeps login timing similar whether or not the account exists
const DUMMY_HASH = bcrypt.hashSync(randomBytes(8).toString('hex'), 10);

app.post('/api/auth/signup', async (req, res) => {
  try {
    const p = signupSchema.safeParse(req.body);
    if (!p.success) return bad(res, p.error.issues.map(i => i.message).join(', '));
    const { password, ...d } = p.data;
    const existing = await prisma.user.findFirst({
      where: { OR: [{ email: { equals: d.email, mode: 'insensitive' } }, { username: { equals: d.username, mode: 'insensitive' } }] }
    });
    if (existing) return bad(res, 'Username or email already registered');
    const user = await prisma.user.create({
      data: { ...d, villainClass: d.villainClass || 'HENCHMAN', lairLocation: d.lairLocation || 'Unknown Lair', passwordHash: await bcrypt.hash(password, 10) }
    });
    const { passwordHash: _, ...safe } = user;
    res.status(201).json({ user: safe, token: sign(user.id) });
  } catch (err) {
    // Two simultaneous signups can slip past the check above; the DB unique constraint catches them
    if ((err as any)?.code === 'P2002') return bad(res, 'Username or email already registered');
    console.error('Signup error:', err); res.status(500).json({ error: 'Internal server error during registration' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const p = loginSchema.safeParse(req.body);
    if (!p.success) return bad(res, 'Identifier and password are required');
    const { identifier, password } = p.data;
    const user = await prisma.user.findFirst({
      where: { OR: [{ email: { equals: identifier, mode: 'insensitive' } }, { username: { equals: identifier, mode: 'insensitive' } }] }
    });
    // Same response for "no such user" and "wrong password" so accounts can't be enumerated
    const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);
    if (!user || !ok) return res.status(401).json({ error: 'Invalid credentials' });
    if (user.banned) return res.status(403).json({ error: 'This account has been banned' });
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
  try { res.json(await prisma.user.findMany({ where: { banned: false }, select: directoryUser })); }
  catch { res.status(500).json({ error: 'Failed to retrieve villain directory' }); }
});

const profileSchema = z.object({
  villainName: z.string().trim().min(1).max(60).optional(),
  headline: z.string().max(120).optional(),
  catchphrase: z.string().max(120).optional(),
  nemesis: z.string().max(60).optional(),
  evilCv: z.string().max(2000).optional(),
  lairLocation: z.string().max(100).optional(),
  avatarUrl: z.string().max(2_000_000).refine(v => v === '' || AVATAR_RE.test(v), 'Avatar must be a PNG/JPEG/GIF/WebP image or an https URL').optional()
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
    const p = z.object({ oldPassword: z.string().max(100), newPassword: z.string().min(6).max(72) }).safeParse(req.body);
    if (!p.success) return bad(res, 'Invalid password change');
    const u = await prisma.user.findUnique({ where: { id: req.params.id } });
    if (!u || !(await bcrypt.compare(p.data.oldPassword, u.passwordHash))) return bad(res, 'Invalid password change');
    await prisma.user.update({ where: { id: u.id }, data: { passwordHash: await bcrypt.hash(p.data.newPassword, 10) } });
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
    const rows = await prisma.message.groupBy({ by: ['senderId'], where: { recipientId: req.params.userId, readAt: null, OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }, _count: true });
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
    const me = (req as any).user;
    const p = z.object({ authorId: z.string(), content: z.string().min(1).max(1000) }).safeParse({ ...req.body, authorId: me.id });
    if (!p.success) return bad(res, p.error.flatten());
    const post = await prisma.post.create({ data: p.data });
    bump(p.data.authorId, 5);
    const names = [...new Set((p.data.content.match(/@([a-zA-Z0-9_]{2,30})/g) || []).map(m => m.slice(1)))];
    if (names.length) {
      const us = await prisma.user.findMany({ where: { username: { in: names } }, select: { id: true } });
      us.forEach(u => u.id !== p.data.authorId && notify(u.id, 'mention', `${me.villainName} mentioned you in a post`));
    }
    io.emit('new_post', post);
    res.status(201).json(post);
  } catch { res.status(500).json({ error: 'Failed to publish scheme' }); }
});

app.post('/api/posts/:id/like', async (req, res) => {
  try {
    const me = (req as any).user;
    const key = { postId_userId: { postId: req.params.id, userId: me.id } };
    const existing = await prisma.like.findUnique({ where: key });
    if (existing) await prisma.like.delete({ where: key });
    else {
      const l = await prisma.like.create({ data: { postId: req.params.id, userId: me.id }, include: { post: { select: { authorId: true } } } });
      if (l.post.authorId !== l.userId) notify(l.post.authorId, 'like', `${me.villainName} gave your post an Evil Nod`);
    }
    res.json({ liked: !existing });
  } catch { res.status(500).json({ error: 'Failed to toggle like' }); }
});

app.post('/api/posts/:id/comments', async (req, res) => {
  try {
    const me = (req as any).user;
    const c = z.object({ authorId: z.string(), content: z.string().min(1).max(500) }).safeParse({ ...req.body, authorId: me.id });
    if (!c.success) return bad(res, c.error.flatten());
    const cm = await prisma.comment.create({ data: { ...c.data, postId: req.params.id }, include: { post: { select: { authorId: true } } } });
    if (cm.post.authorId !== cm.authorId) notify(cm.post.authorId, 'comment', `${me.villainName} commented on your post`);
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
      take: 200,
      include: { claimer: { select: { villainName: true } } }
    }));
  } catch { res.status(500).json({ error: 'Failed to retrieve bounty contracts' }); }
});

app.post('/api/bounties', async (req, res) => {
  try {
    const me = (req as any).user;
    const p = z.object({
      title: z.string().min(1).max(100), target: z.string().min(1).max(100),
      description: z.string().max(1000).optional(), reward: z.string().min(1).max(100),
      creatorId: z.string(), category: z.enum(['GENERAL', 'SABOTAGE', 'THEFT', 'RECON']).optional(),
      expiresAt: z.string().refine(v => v === '' || !isNaN(Date.parse(v)), 'Invalid expiry date').optional(),
      rewardCoins: z.number().int().min(0).max(1000000).optional()
    }).safeParse({ ...req.body, creatorId: me.id });
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
    const me = (req as any).user;
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.status !== 'OPEN' || b.creatorId === me.id || (b.expiresAt && b.expiresAt < new Date())) return bad(res, 'Contract unavailable');
    // Atomic: only one claimer can flip OPEN -> IN_PROGRESS
    const r = await prisma.bounty.updateMany({ where: { id: b.id, status: 'OPEN' }, data: { status: 'IN_PROGRESS', claimerId: me.id } });
    if (!r.count) return bad(res, 'Contract unavailable');
    const u = await prisma.bounty.findUnique({ where: { id: b.id } });
    notify(b.creatorId, 'bounty', `${me.villainName} claimed your contract "${b.title}"`);
    io.emit('new_bounty_posted', u);
    res.json(u);
  } catch { res.status(500).json({ error: 'Failed to claim contract' }); }
});

app.post('/api/bounties/:id/complete', async (req, res) => {
  try {
    const me = (req as any).user;
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.creatorId !== me.id) return res.status(403).json({ error: 'Only the creator can complete it' });
    if (b.status !== 'IN_PROGRESS' || !b.claimerId) return bad(res, 'Contract is not in progress');
    const claimerId = b.claimerId;
    const u = await prisma.$transaction(async tx => {
      // Atomic status flip first, so two simultaneous requests can't both pay out
      const r = await tx.bounty.updateMany({ where: { id: b.id, status: 'IN_PROGRESS' }, data: { status: 'COMPLETED' } });
      if (!r.count) throw new Error('NOT_IN_PROGRESS');
      await tx.user.update({ where: { id: claimerId }, data: { coins: { increment: b.rewardCoins }, notoriety: { increment: 10 } } });
      return tx.bounty.findUnique({ where: { id: b.id } });
    });
    notify(claimerId, 'bounty', `Contract "${b.title}" completed${b.rewardCoins ? ` — you were paid ${b.rewardCoins} 🪙` : ''}`);
    io.emit('new_bounty_posted', u);
    res.json(u);
  } catch (err) {
    if ((err as Error).message === 'NOT_IN_PROGRESS') return bad(res, 'Contract is not in progress');
    res.status(500).json({ error: 'Failed to complete contract' });
  }
});

// ==================== SIGHTINGS ====================
app.get('/api/sightings', async (_req, res) => {
  try { res.json(await prisma.heroSighting.findMany({ orderBy: { createdAt: 'desc' }, take: 50 })); }
  catch { res.status(500).json({ error: 'Failed to fetch threat feed' }); }
});

app.post('/api/sightings/:id/verify', async (req, res) => {
  try {
    const me = (req as any).user;
    const confirm = !!req.body.confirm;
    const s = await prisma.$transaction(async tx => {
      const sighting = await tx.heroSighting.findUnique({ where: { id: req.params.id } });
      if (!sighting) throw new Error('NOT_FOUND');
      if (sighting.reporterId === me.id) throw new Error('OWN_REPORT');
      const key = { sightingId_userId: { sightingId: sighting.id, userId: me.id } };
      const prev = await tx.sightingVote.findUnique({ where: key });
      if (prev && prev.confirm === confirm) return sighting; // same vote again: nothing changes
      if (prev) await tx.sightingVote.update({ where: key, data: { confirm } });
      else await tx.sightingVote.create({ data: { sightingId: sighting.id, userId: me.id, confirm } });
      // A changed vote moves one count from the old side to the new side
      return tx.heroSighting.update({
        where: { id: sighting.id },
        data: confirm
          ? { confirms: { increment: 1 }, ...(prev ? { falseAlarms: { decrement: 1 } } : {}) }
          : { falseAlarms: { increment: 1 }, ...(prev ? { confirms: { decrement: 1 } } : {}) }
      });
    });
    io.emit('sighting_updated', s);
    res.json(s);
  } catch (err) {
    const m = (err as Error).message;
    if (m === 'NOT_FOUND') return res.status(404).json({ error: 'Sighting not found' });
    if (m === 'OWN_REPORT') return bad(res, 'You cannot verify your own report');
    if ((err as any)?.code === 'P2002') return bad(res, 'Vote already recorded');
    res.status(500).json({ error: 'Failed to verify sighting' });
  }
});

// ==================== ECONOMY, INTEL, SEARCH ====================
app.post('/api/bounties/:id/cancel', async (req, res) => {
  try {
    const me = (req as any).user;
    const b = await prisma.bounty.findUnique({ where: { id: req.params.id } });
    if (!b || b.creatorId !== me.id || b.status !== 'OPEN') return bad(res, 'Cannot cancel this contract');
    await prisma.$transaction(async tx => {
      // Atomic: if someone claims it at the same moment, the delete matches nothing and no refund is issued
      const r = await tx.bounty.deleteMany({ where: { id: b.id, creatorId: me.id, status: 'OPEN' } });
      if (!r.count) throw new Error('CANNOT_CANCEL');
      if (b.rewardCoins) await tx.user.update({ where: { id: me.id }, data: { coins: { increment: b.rewardCoins } } });
    });
    io.emit('new_bounty_posted', { id: b.id });
    res.json({ ok: true });
  } catch (err) {
    if ((err as Error).message === 'CANNOT_CANCEL') return bad(res, 'Cannot cancel this contract');
    res.status(500).json({ error: 'Failed to cancel contract' });
  }
});

app.get('/api/leaderboard', ah(async (_req, res) => {
  res.json(await prisma.user.findMany({ where: { banned: false }, orderBy: { coins: 'desc' }, take: 10, select: { villainName: true, username: true, coins: true, notoriety: true } }));
}));

app.get('/api/heroes', ah(async (_req, res) => {
  res.json(await prisma.heroSighting.groupBy({ by: ['heroName'], _count: true, _max: { dangerLevel: true, createdAt: true }, orderBy: { _count: { heroName: 'desc' } }, take: 30 }));
}));

app.get('/api/messages/:userA/:userB/search', ah(async (req, res) => {
  const { userA, userB } = req.params;
  const q = String(req.query.q || '').slice(0, 100);
  res.json(await prisma.message.findMany({
    where: {
      content: { contains: q, mode: 'insensitive' },
      AND: [
        { OR: [{ senderId: userA, recipientId: userB }, { senderId: userB, recipientId: userA }] },
        { OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }] }
      ]
    },
    orderBy: { createdAt: 'asc' }, take: 100
  }));
}));

app.delete('/api/posts/:id', ah(async (req, res) => {
  const me = (req as any).user;
  const p = await prisma.post.findUnique({ where: { id: req.params.id } });
  if (!p || (p.authorId !== me.id && me.role !== 'ADMIN')) return res.status(403).json({ error: 'Forbidden' });
  await prisma.post.delete({ where: { id: p.id } });
  io.emit('new_post', { id: p.id });
  res.json({ ok: true });
}));

// ==================== ADMIN ====================
app.post('/api/admin/users/:id/ban', adminOnly, ah(async (req, res) => {
  if (req.params.id === (req as any).user.id) return bad(res, 'You cannot ban yourself');
  const banned = !!req.body.banned;
  await prisma.user.update({ where: { id: req.params.id }, data: { banned } });
  if (banned) io.in(req.params.id).disconnectSockets(true);
  res.json({ ok: true });
}));
app.post('/api/admin/users/:id/mute', adminOnly, ah(async (req, res) => {
  const minutes = Math.max(0, Math.min(Number(req.body.minutes) || 0, 60 * 24 * 30));
  await prisma.user.update({ where: { id: req.params.id }, data: { mutedUntil: minutes ? new Date(Date.now() + minutes * 60_000) : null } });
  res.json({ ok: true });
}));

// ==================== SOCIAL ====================
const SKILLS = ['Mind Control', 'Explosives', 'Hacking', 'Henchman Management', 'Doomsday Devices', 'Evil Laughter'];

app.get('/api/profile/:id', ah(async (req, res) => {
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
}));

app.post('/api/follow/:targetId', ah(async (req, res) => {
  const me = (req as any).user, t = req.params.targetId;
  if (t === me.id) return bad(res, 'You cannot follow yourself');
  const key = { followerId_followedId: { followerId: me.id, followedId: t } };
  const ex = await prisma.follow.findUnique({ where: key });
  if (ex) await prisma.follow.delete({ where: key });
  else { await prisma.follow.create({ data: { followerId: me.id, followedId: t } }); notify(t, 'follow', `${me.villainName} is now following you`); }
  res.json({ following: !ex });
}));

app.post('/api/endorse/:targetId', ah(async (req, res) => {
  const me = (req as any).user, t = req.params.targetId, skill = String(req.body.skill);
  if (t === me.id || !SKILLS.includes(skill)) return bad(res, 'Invalid endorsement');
  const key = { endorserId_endorsedId_skill: { endorserId: me.id, endorsedId: t, skill } };
  const already = await prisma.endorsement.findUnique({ where: key });
  if (!already) {
    await prisma.endorsement.upsert({ where: key, update: {}, create: { endorserId: me.id, endorsedId: t, skill } });
    notify(t, 'endorse', `${me.villainName} endorsed you for ${skill}`); // only the first time, so re-clicking can't spam
  }
  res.json({ ok: true });
}));

app.get('/api/notifications', ah(async (req, res) => {
  const me = (req as any).user.id;
  const [items, unread] = await Promise.all([
    prisma.notification.findMany({ where: { userId: me }, orderBy: { createdAt: 'desc' }, take: 30 }),
    prisma.notification.count({ where: { userId: me, read: false } })
  ]);
  res.json({ items, unread });
}));
app.post('/api/notifications/read', ah(async (req, res) => {
  await prisma.notification.updateMany({ where: { userId: (req as any).user.id, read: false }, data: { read: true } });
  res.json({ ok: true });
}));

app.get('/api/trending', ah(async (_req, res) => {
  const ps = await prisma.post.findMany({ orderBy: { createdAt: 'desc' }, take: 200, select: { content: true } });
  const c: Record<string, number> = {};
  ps.forEach(p => (p.content.match(/#[a-zA-Z0-9_]{2,30}/g) || []).forEach(t => { const k = t.slice(1).toLowerCase(); c[k] = (c[k] || 0) + 1; }));
  res.json(Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 8));
}));

// ==================== SECRET SOCIETIES ====================
const isMember = (societyId: string, userId: string) =>
  prisma.societyMember.findUnique({ where: { societyId_userId: { societyId, userId } } });

app.get('/api/societies', ah(async (req, res) => {
  const ms = await prisma.societyMember.findMany({ where: { userId: (req as any).user.id }, include: { society: true } });
  res.json(ms.map(m => m.society));
}));
app.post('/api/societies', ah(async (req, res) => {
  const p = z.object({ name: z.string().trim().min(2).max(50) }).safeParse(req.body);
  if (!p.success) return bad(res, 'Society name must be 2-50 characters');
  const me = (req as any).user.id;
  const s = await prisma.society.create({ data: { name: p.data.name, inviteCode: randomBytes(4).toString('hex'), members: { create: { userId: me } } } });
  io.in(me).socketsJoin('soc:' + s.id);
  res.status(201).json(s);
}));
app.post('/api/societies/join', ah(async (req, res) => {
  const me = (req as any).user.id;
  const s = await prisma.society.findUnique({ where: { inviteCode: String(req.body.code || '').trim() } });
  if (!s) return bad(res, 'Invalid invite code');
  await prisma.societyMember.upsert({ where: { societyId_userId: { societyId: s.id, userId: me } }, update: {}, create: { societyId: s.id, userId: me } });
  io.in(me).socketsJoin('soc:' + s.id);
  res.json(s);
}));
app.get('/api/societies/:id/messages', ah(async (req, res) => {
  if (!(await isMember(req.params.id, (req as any).user.id))) return res.status(403).json({ error: 'Members only' });
  res.json(await prisma.societyMessage.findMany({ where: { societyId: req.params.id }, orderBy: { createdAt: 'asc' }, take: 200, include: { sender: { select: { villainName: true } } } }));
}));

// ==================== ERROR HANDLER (must come after all routes) ====================
app.use((err: any, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'Malformed JSON' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large' });
  if (err?.code === 'P2025' || err?.code === 'P2003') return res.status(404).json({ error: 'Not found' }); // missing record / bad reference
  if (err?.code === 'P2002') return res.status(400).json({ error: 'Already exists' });
  console.error('Unhandled route error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ==================== SOCKET.IO ====================
const dmSchema = z.object({
  recipientId: z.string().min(1).max(64),
  content: z.string().max(2000).nullish(),
  imageUrl: z.string().max(MAX_IMAGE_CHARS).regex(IMAGE_RE, 'Unsupported image format').nullish(),
  replyToId: z.string().max(64).nullish(),
  ttl: z.unknown().optional()
}).refine(d => (d.content && d.content.trim().length > 0) || d.imageUrl, { message: 'Message is empty' });

// Per-socket flood control: max `limit` events per `windowMs` for a named bucket
function allow(socket: Socket, key: string, limit: number, windowMs: number): boolean {
  const buckets = (socket.data.buckets ||= {}) as Record<string, { count: number; reset: number }>;
  const now = Date.now();
  const b = buckets[key];
  if (!b || now > b.reset) { buckets[key] = { count: 1, reset: now + windowMs }; return true; }
  return ++b.count <= limit;
}

io.on('connection', (socket) => {
  const me: string = socket.data.userId;
  console.log(`[CLIENT CONNECTED]: ${socket.id}`);

  // Flood control for every event, and identity fields in payloads are always overwritten with the token's user
  socket.use((packet, next) => {
    if (!allow(socket, 'all', 100, 10_000)) return next(new Error('rate_limited'));
    const p = packet[1];
    if (p && typeof p === 'object' && !Array.isArray(p))
      for (const k of ['senderId', 'readerId', 'userId', 'reporterId', 'from']) if (k in p) p[k] = me;
    next();
  });

  // Wrapper: payload is always an object, and any error is logged instead of crashing the server.
  // Handlers use `me` (from the verified token) and never read identity from the payload.
  const on = (event: string, fn: (d: any) => unknown) =>
    socket.on(event, async (d: any) => {
      try { await fn(d && typeof d === 'object' && !Array.isArray(d) ? d : {}); }
      catch (err) { console.error(`${event} error:`, err); }
    });

  socket.join(me); // personal room, joined server-side
  prisma.societyMember.findMany({ where: { userId: me } })
    .then(ms => ms.forEach(m => socket.join('soc:' + m.societyId))).catch(() => {});

  // Kept for compatibility with existing clients; the server decides which room you join
  on('join_user_room', () => { socket.join(me); });

  on('send_direct_message', async (d) => {
    if (!allow(socket, 'dm', 20, 10_000)) { socket.emit('dispatch_error', 'Slow down: too many transmissions.'); return; }
    const p = dmSchema.safeParse(d);
    if (!p.success) { socket.emit('dispatch_error', p.error.issues[0]?.message || 'Invalid message'); return; }
    if (await muted(me)) { socket.emit('dispatch_error', 'You are muted.'); return; }
    const { recipientId, content, imageUrl, replyToId, ttl } = p.data;
    const recipient = await prisma.user.findUnique({ where: { id: recipientId }, select: { id: true } });
    if (!recipient) { socket.emit('dispatch_error', 'Recipient not found.'); return; }
    const message = await prisma.message.create({
      data: {
        senderId: me, recipientId, content: content || '', imageUrl: imageUrl || null, replyToId: replyToId || null,
        expiresAt: Number(ttl) > 0 ? new Date(Date.now() + Math.min(Number(ttl), 86400) * 1000) : null
      }
    });
    bump(me, 1);
    io.to(recipientId).to(me).emit('receive_direct_message', message);
  });

  on('typing', (d) => {
    if (typeof d.to === 'string' && d.to) io.to(d.to).emit('typing', { from: me, name: socket.data.name });
  });

  on('mark_read', async (d) => {
    if (typeof d.otherId !== 'string' || !d.otherId) return; // an undefined filter would match every message
    const r = await prisma.message.updateMany({ where: { senderId: d.otherId, recipientId: me, readAt: null }, data: { readAt: new Date() } });
    // Only notify when something changed. Each client reloads its chat on 'messages_read' and answers with
    // mark_read, so emitting unconditionally made two open chats ping-pong forever.
    if (r.count > 0) io.to(d.otherId).emit('messages_read', { by: me });
  });

  on('react_message', async (d) => {
    if (typeof d.messageId !== 'string' || !['😈', '🔥', '💀'].includes(d.emoji)) return;
    if (await muted(me)) return;
    const m = await prisma.message.findUnique({ where: { id: d.messageId } });
    if (!m || (m.senderId !== me && m.recipientId !== me)) return; // only the two participants can react
    const r = (m.reactions as Record<string, string[]>) || {};
    const has = r[d.emoji]?.includes(me);
    r[d.emoji] = has ? r[d.emoji].filter(i => i !== me) : [...(r[d.emoji] || []), me];
    const updated = await prisma.message.update({ where: { id: d.messageId }, data: { reactions: r } });
    io.to(m.senderId).to(m.recipientId).emit('message_updated', updated);
  });

  on('delete_message', async (d) => {
    if (typeof d.messageId !== 'string') return;
    const m = await prisma.message.findUnique({ where: { id: d.messageId } });
    if (!m || m.senderId !== me) return;
    await prisma.message.delete({ where: { id: d.messageId } });
    io.to(m.senderId).to(m.recipientId).emit('message_deleted', { id: d.messageId });
  });

  on('set_status', async (d) => {
    if (!['online', 'offline', 'plotting'].includes(d.status)) return;
    await prisma.user.update({ where: { id: me }, data: { status: d.status } });
    io.emit('status_changed', { userId: me, status: d.status });
  });

  on('report_hero_sighting', async (d) => {
    if (!allow(socket, 'sighting', 10, 60_000)) { socket.emit('dispatch_error', 'Slow down: too many reports.'); return; }
    if (typeof d.heroName !== 'string' || typeof d.location !== 'string' || !d.heroName.trim() || !d.location.trim()) return;
    if (await muted(me)) { socket.emit('dispatch_error', 'You are muted.'); return; }
    const sighting = await prisma.heroSighting.create({
      data: {
        reporterId: me, heroName: d.heroName.trim().slice(0, 80), location: d.location.trim().slice(0, 120),
        dangerLevel: Math.min(5, Math.max(1, parseInt(d.dangerLevel) || 1))
      }
    });
    io.emit('global_hero_alert', sighting);
    bump(me, 2);
  });

  on('pin_message', async (d) => {
    if (typeof d.messageId !== 'string' || (await muted(me))) return;
    const m = await prisma.message.findUnique({ where: { id: d.messageId } });
    if (!m || (m.senderId !== me && m.recipientId !== me)) return;
    const u = await prisma.message.update({ where: { id: d.messageId }, data: { pinned: !m.pinned } });
    io.to(m.senderId).to(m.recipientId).emit('message_updated', u);
  });

  on('edit_message', async (d) => {
    if (typeof d.messageId !== 'string' || typeof d.content !== 'string' || !d.content.trim() || d.content.length > 2000 || (await muted(me))) return;
    const m = await prisma.message.findUnique({ where: { id: d.messageId } });
    if (!m || m.senderId !== me) return;
    const u = await prisma.message.update({ where: { id: d.messageId }, data: { content: d.content, editedAt: new Date() } });
    io.to(m.senderId).to(m.recipientId).emit('message_updated', u);
  });

  on('send_society_message', async (d) => {
    if (typeof d.societyId !== 'string' || typeof d.content !== 'string' || !d.content || d.content.length > 2000) return;
    if (!allow(socket, 'society', 20, 10_000)) { socket.emit('dispatch_error', 'Slow down: too many transmissions.'); return; }
    if ((await muted(me)) || !(await isMember(d.societyId, me))) return;
    const m = await prisma.societyMessage.create({ data: { societyId: d.societyId, senderId: me, content: d.content }, include: { sender: { select: { villainName: true } } } });
    bump(me, 1);
    io.to('soc:' + d.societyId).emit('society_message', m);
  });

  socket.on('disconnect', async () => {
    console.log(`[CLIENT DISCONNECTED]: ${socket.id}`);
    try {
      // Only go offline when this was the user's last open connection (other tabs/devices keep them online)
      if ((await io.in(me).fetchSockets()).length === 0) {
        await prisma.user.update({ where: { id: me }, data: { status: 'offline' } });
        io.emit('status_changed', { userId: me, status: 'offline' });
      }
    } catch { /* best effort */ }
  });
});

// A stray rejected promise should be logged, not take the whole server down
process.on('unhandledRejection', (err) => console.error('Unhandled rejection:', err));

setInterval(() => prisma.message.deleteMany({ where: { expiresAt: { lt: new Date() } } }).catch(() => {}), 30_000);

if (process.env.ADMIN_USERNAME)
  prisma.user.updateMany({ where: { username: process.env.ADMIN_USERNAME }, data: { role: 'ADMIN' } }).catch(console.error);

server.listen(PORT, () => console.log(`DOOMSTACK backend server running on port ${PORT}`));