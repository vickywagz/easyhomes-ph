# easyHomes PH — React + Node starter

A Port Harcourt-focused rental discovery platform with Nigerian property context.

## Stack
- Frontend: React + Vite
- API: Node.js + Express
- Database: PostgreSQL + Prisma
- Security baseline: Helmet, rate limiting, CORS allowlist, request validation, password hashing, JWT in httpOnly cookie, role checks

## Local development
Requirements: Node.js 20+, PostgreSQL.

1. Copy `.env.example` to `server/.env` and set a strong `JWT_SECRET`, `DATABASE_URL`, `CLIENT_ORIGIN`.
2. Install dependencies:
   - `cd server && npm install`
   - `cd ../client && npm install`
3. Create database tables:
   - `cd ../server && npx prisma migrate dev --name init`
4. Seed sample listings:
   - `npm run seed`
5. Run the API and frontend in separate terminals:
   - `cd server && npm run dev`
   - `cd client && npm run dev`

Frontend defaults to `http://localhost:5173`; API defaults to `http://localhost:4000`.

## Important before hosting
- Configure HTTPS and set `COOKIE_SECURE=true`.
- Set `CLIENT_ORIGIN` to your exact production frontend origin.
- Use a managed PostgreSQL database and persistent image storage (S3-compatible or Cloudinary); don't store uploads on an ephemeral server filesystem.
- Add email/phone verification, account recovery, admin MFA and audit logging before real public launch.
- The sample listing content is demonstration data. Replace it with real listings and only publish photos/contact details with permission.
- Never expose landlord phone numbers for unverified or unapproved listings.
- Area condition reports are user reports, not guarantees. Display source and last-confirmed date.
- This is a starter implementation, not a substitute for a security review or production deployment testing.
