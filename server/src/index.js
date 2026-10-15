import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { z } from 'zod';

const app = express();
const prisma = new PrismaClient();
const PORT = Number(process.env.PORT || 4000);
const production = process.env.NODE_ENV === 'production';
const allowedOrigin = process.env.CLIENT_ORIGIN || 'http://localhost:5173';
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be set to a random secret of at least 32 characters.');
}

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: allowedOrigin, credentials: true, methods: ['GET','POST','PATCH','DELETE'] }));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());
app.use('/api', rateLimit({ windowMs: 15 * 60 * 1000, limit: 150, standardHeaders: 'draft-7', legacyHeaders: false }));

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const registerSchema = z.object({
  fullName: z.string().trim().min(2).max(100),
  email: z.string().trim().email().max(254).transform(v => v.toLowerCase()),
  phone: z.string().trim().max(25).optional(),
  password: z.string().min(12).max(128),
  role: z.enum(['RENTER','LANDLORD']).default('RENTER')
});
const loginSchema = z.object({ email: z.string().email().transform(v => v.toLowerCase()), password: z.string().min(1).max(128) });
const propertyQuery = z.object({
  area: z.string().trim().max(80).optional(),
  type: z.string().trim().max(40).optional(),
  minRent: z.coerce.number().int().min(0).optional(),
  maxRent: z.coerce.number().int().min(0).optional(),
  bedrooms: z.coerce.number().int().min(0).max(20).optional()
});

function setAuthCookie(res, user) {
  const token = jwt.sign({ sub: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '2h', issuer: 'easyhomes-ph' });
  res.cookie('eh_session', token, {
    httpOnly: true, secure: process.env.COOKIE_SECURE === 'true' || production,
    sameSite: 'lax', path: '/', maxAge: 2 * 60 * 60 * 1000
  });
}
const auth = asyncRoute(async (req, res, next) => {
  const token = req.cookies.eh_session;
  if (!token) return res.status(401).json({ error: 'Please sign in.' });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET, { issuer: 'easyhomes-ph' });
    const user = await prisma.user.findUnique({ where: { id: payload.sub }, select: { id: true, role: true, fullName: true, email: true } });
    if (!user) return res.status(401).json({ error: 'Session is no longer valid.' });
    req.user = user; next();
  } catch { return res.status(401).json({ error: 'Session expired. Please sign in again.' }); }
});
const roles = (...allowed) => (req, res, next) => {
  if (!req.user || !allowed.includes(req.user.role)) return res.status(403).json({ error: 'Not authorised.' });
  next();
};

app.get('/api/health', (_req, res) => res.json({ status: 'ok', service: 'easyHomes PH API' }));

app.post('/api/auth/register', rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }), asyncRoute(async (req, res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Check your details. Password must be at least 12 characters.' });
  const { fullName, email, phone, password, role } = parsed.data;
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    // Public registration cannot create administrators.
    const user = await prisma.user.create({ data: { fullName, email, phone, passwordHash, role }, select: { id: true, fullName: true, email: true, role: true } });
    setAuthCookie(res, user);
    res.status(201).json({ user });
  } catch (e) {
    if (e.code === 'P2002') return res.status(409).json({ error: 'An account with this email already exists.' });
    throw e;
  }
}));
app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, limit: 10 }), asyncRoute(async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Enter a valid email and password.' });
  const user = await prisma.user.findUnique({ where: { email: parsed.data.email } });
  if (!user || !(await bcrypt.compare(parsed.data.password, user.passwordHash))) return res.status(401).json({ error: 'Email or password is incorrect.' });
  setAuthCookie(res, user);
  res.json({ user: { id: user.id, fullName: user.fullName, email: user.email, role: user.role } });
}));
app.post('/api/auth/logout', (_req, res) => {
  res.clearCookie('eh_session', { httpOnly: true, secure: process.env.COOKIE_SECURE === 'true' || production, sameSite: 'lax', path: '/' });
  res.status(204).end();
});
app.get('/api/auth/me', auth, (req, res) => res.json({ user: req.user }));

app.get('/api/properties', asyncRoute(async (req, res) => {
  const parsed = propertyQuery.safeParse(req.query);
  if (!parsed.success) return res.status(400).json({ error: 'Invalid search filters.' });
  const q = parsed.data;
  const where = {
    status: 'APPROVED', availability: 'AVAILABLE',
    ...(q.area ? { area: { contains: q.area, mode: 'insensitive' } } : {}),
    ...(q.type ? { propertyType: { equals: q.type, mode: 'insensitive' } } : {}),
    ...(q.minRent !== undefined || q.maxRent !== undefined ? { rentNaira: { ...(q.minRent !== undefined ? { gte: q.minRent } : {}), ...(q.maxRent !== undefined ? { lte: q.maxRent } : {}) } } : {}),
    ...(q.bedrooms !== undefined && q.bedrooms > 0 ? { bedrooms: q.bedrooms } : {})
  };
  const properties = await prisma.property.findMany({
    where, orderBy: [{ lastConfirmedAt: 'desc' }, { createdAt: 'desc' }], take: 60,
    select: { id: true, title: true, area: true, propertyType: true, rentNaira: true, rentPeriod: true, bedrooms: true, bathrooms: true, amenities: true, imageUrls: true, verification: true, verifiedAt: true, lastConfirmedAt: true, createdAt: true,
      reviews: { where: { moderation: 'APPROVED' }, select: { overall: true } },
      areaReports: { where: { moderation: 'APPROVED' }, select: { type: true, rating: true, summary: true, observedAt: true, createdAt: true }, orderBy: { createdAt: 'desc' }, take: 5 }
    }
  });
  res.json({ properties: properties.map(p => ({ ...p, reviewCount: p.reviews.length, rating: p.reviews.length ? Number((p.reviews.reduce((s,r)=>s+r.overall,0)/p.reviews.length).toFixed(1)) : null, reviews: undefined })) });
}));

app.get('/api/properties/:id', asyncRoute(async (req, res) => {
  const property = await prisma.property.findFirst({
    where: { id: req.params.id, status: 'APPROVED' },
    select: { id: true, title: true, description: true, area: true, addressApprox: true, propertyType: true, rentNaira: true, rentPeriod: true, bedrooms: true, bathrooms: true, amenities: true, imageUrls: true, verification: true, verifiedAt: true, lastConfirmedAt: true, createdAt: true,
      landlord: { select: { fullName: true, phone: true } },
      reviews: { where: { moderation: 'APPROVED' }, select: { id: true, overall: true, landlord: true, listingMatch: true, utilities: true, environment: true, comment: true, createdAt: true, author: { select: { fullName: true } } }, orderBy: { createdAt: 'desc' }, take: 30 },
      areaReports: { where: { moderation: 'APPROVED' }, select: { id: true, type: true, rating: true, summary: true, details: true, sourceLabel: true, observedAt: true, createdAt: true }, orderBy: { createdAt: 'desc' }, take: 30 }
    }
  });
  if (!property) return res.status(404).json({ error: 'Property not found.' });
  // Phone is only shown for approved listings, after checking publication permissions in admin workflow.
  res.json({ property });
}));

const viewingSchema = z.object({
  name: z.string().trim().min(2).max(100),
  phone: z.string().trim().min(7).max(25),
  preferredAt: z.string().datetime().optional(),
  message: z.string().trim().max(1000).optional()
});
app.post('/api/properties/:id/viewings', rateLimit({ windowMs: 60 * 60 * 1000, limit: 5 }), asyncRoute(async (req, res) => {
  const parsed = viewingSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Please check the viewing request details.' });
  const property = await prisma.property.findFirst({ where: { id: req.params.id, status: 'APPROVED', availability: 'AVAILABLE' }, select: { id: true } });
  if (!property) return res.status(404).json({ error: 'This property is not currently available for viewing.' });
  const created = await prisma.viewingRequest.create({ data: { propertyId: property.id, ...parsed.data, preferredAt: parsed.data.preferredAt ? new Date(parsed.data.preferredAt) : undefined }, select: { id: true, createdAt: true } });
  res.status(201).json({ message: 'Viewing request received. The advertiser will need to confirm the appointment.', request: created });
}));

const reviewSchema = z.object({
  overall: z.number().int().min(1).max(5),
  landlord: z.number().int().min(1).max(5).optional(),
  listingMatch: z.number().int().min(1).max(5).optional(),
  utilities: z.number().int().min(1).max(5).optional(),
  environment: z.number().int().min(1).max(5).optional(),
  comment: z.string().trim().min(20).max(1500),
  experience: z.enum(['VIEWED','TENANT','OTHER'])
});
app.post('/api/properties/:id/reviews', auth, rateLimit({ windowMs: 60 * 60 * 1000, limit: 5 }), asyncRoute(async (req, res) => {
  const parsed = reviewSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Review details are invalid. Please provide a comment of at least 20 characters.' });
  const property = await prisma.property.findFirst({ where: { id: req.params.id, status: 'APPROVED' }, select: { id: true } });
  if (!property) return res.status(404).json({ error: 'Property not found.' });
  try {
    const review = await prisma.review.create({ data: { propertyId: property.id, authorId: req.user.id, ...parsed.data, moderation: 'PENDING' }, select: { id: true, moderation: true, createdAt: true } });
    res.status(201).json({ message: 'Review submitted for moderation.', review });
  } catch (e) {
    if (e.code === 'P2002') return res.status(409).json({ error: 'You have already reviewed this property.' });
    throw e;
  }
}));

const areaReportSchema = z.object({
  type: z.enum(['ELECTRICITY','WATER','FLOODING','ROAD_ACCESS','SECURITY','NETWORK','OTHER']),
  rating: z.number().int().min(1).max(5).optional(),
  summary: z.string().trim().min(5).max(140),
  details: z.string().trim().max(1200).optional(),
  observedAt: z.string().datetime().optional()
});
app.post('/api/properties/:id/area-reports', auth, rateLimit({ windowMs: 60 * 60 * 1000, limit: 8 }), asyncRoute(async (req, res) => {
  const parsed = areaReportSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Please check the area report details.' });
  const property = await prisma.property.findFirst({ where: { id: req.params.id, status: 'APPROVED' }, select: { id: true } });
  if (!property) return res.status(404).json({ error: 'Property not found.' });
  const report = await prisma.areaReport.create({ data: { propertyId: property.id, authorId: req.user.id, ...parsed.data, observedAt: parsed.data.observedAt ? new Date(parsed.data.observedAt) : undefined }, select: { id: true, moderation: true, createdAt: true } });
  res.status(201).json({ message: 'Area report submitted for moderation.', report });
}));

app.post('/api/properties', auth, roles('LANDLORD','ADMIN'), asyncRoute(async (req, res) => {
  const schema = z.object({
    title: z.string().trim().min(8).max(140), description: z.string().trim().min(30).max(4000),
    area: z.string().trim().min(2).max(80), addressApprox: z.string().trim().max(200).optional(),
    propertyType: z.string().trim().min(3).max(40), rentNaira: z.number().int().positive().max(1000000000),
    rentPeriod: z.enum(['year','month']).default('year'), bedrooms: z.number().int().min(0).max(20),
    bathrooms: z.number().int().min(0).max(20), amenities: z.array(z.string().max(50)).max(30).default([]),
    imageUrls: z.array(z.string().url().refine(u => u.startsWith('https://'), 'HTTPS image URL required')).max(20).default([])
  });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: 'Please check the property details.' });
  const property = await prisma.property.create({ data: { ...parsed.data, landlordId: req.user.id, status: 'PENDING', verification: 'UNVERIFIED' }, select: { id: true, title: true, status: true } });
  res.status(201).json({ message: 'Listing submitted for admin review.', property });
}));

app.get('/api/admin/moderation', auth, roles('ADMIN'), asyncRoute(async (_req, res) => {
  const [properties, reviews, reports] = await Promise.all([
    prisma.property.findMany({ where: { status: 'PENDING' }, select: { id:true,title:true,area:true,createdAt:true,landlord:{select:{fullName:true,email:true,phone:true}} }, take:100, orderBy:{createdAt:'asc'} }),
    prisma.review.findMany({ where:{moderation:'PENDING'}, select:{id:true,comment:true,overall:true,createdAt:true,property:{select:{title:true,area:true}},author:{select:{fullName:true,email:true}}}, take:100, orderBy:{createdAt:'asc'} }),
    prisma.areaReport.findMany({ where:{moderation:'PENDING'}, select:{id:true,type:true,summary:true,details:true,createdAt:true,property:{select:{title:true,area:true}},author:{select:{fullName:true,email:true}}}, take:100, orderBy:{createdAt:'asc'} })
  ]);
  res.json({ properties, reviews, reports });
}));
app.patch('/api/admin/properties/:id', auth, roles('ADMIN'), asyncRoute(async (req, res) => {
  const schema = z.object({ decision:z.enum(['APPROVED','REJECTED']), verification:z.enum(['UNVERIFIED','DETAILS_CHECKED','VERIFIED']).optional(), verificationNotes:z.string().trim().max(1000).optional() });
  const parsed = schema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:'Invalid moderation decision.'});
  const data = { status:parsed.data.decision, verification:parsed.data.verification || 'UNVERIFIED', verificationNotes:parsed.data.verificationNotes, verifiedAt:parsed.data.verification && parsed.data.verification !== 'UNVERIFIED' ? new Date() : null };
  const updated = await prisma.property.update({ where:{id:req.params.id}, data, select:{id:true,status:true,verification:true} });
  await prisma.auditLog.create({data:{actorId:req.user.id,action:`PROPERTY_${parsed.data.decision}`,entity:'Property',entityId:updated.id}});
  res.json({property:updated});
}));
app.patch('/api/admin/reviews/:id', auth, roles('ADMIN'), asyncRoute(async (req, res) => {
  const schema = z.object({decision:z.enum(['APPROVED','REJECTED'])});
  const parsed=schema.safeParse(req.body); if(!parsed.success) return res.status(400).json({error:'Invalid decision.'});
  const review=await prisma.review.update({where:{id:req.params.id},data:{moderation:parsed.data.decision},select:{id:true,moderation:true}});
  await prisma.auditLog.create({data:{actorId:req.user.id,action:`REVIEW_${parsed.data.decision}`,entity:'Review',entityId:review.id}});
  res.json({review});
}));
app.patch('/api/admin/area-reports/:id', auth, roles('ADMIN'), asyncRoute(async (req, res) => {
  const schema = z.object({decision:z.enum(['APPROVED','REJECTED'])});
  const parsed=schema.safeParse(req.body); if(!parsed.success) return res.status(400).json({error:'Invalid decision.'});
  const report=await prisma.areaReport.update({where:{id:req.params.id},data:{moderation:parsed.data.decision},select:{id:true,moderation:true}});
  await prisma.auditLog.create({data:{actorId:req.user.id,action:`AREA_REPORT_${parsed.data.decision}`,entity:'AreaReport',entityId:report.id}});
  res.json({report});
}));

app.use((req,res) => res.status(404).json({error:'Route not found.'}));
app.use((err, req, res, _next) => {
  console.error('API error:', err?.message || 'Unknown error');
  res.status(500).json({ error: production ? 'Something went wrong. Please try again.' : (err?.message || 'Internal server error') });
});
const server = app.listen(PORT, () => console.log(`easyHomes API listening on port ${PORT}`));
process.on('SIGTERM', async () => { server.close(); await prisma.$disconnect(); });
