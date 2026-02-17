# Secure Database Setup (PostgreSQL + Encrypted API)

This project now includes a secure backend that stores app state in PostgreSQL with encryption-at-rest.

## What was added

  - `backend/src/server.js`
  - Token-protected API:
    - `GET /api/state/load?scope=...`
    - `POST /api/state/save`
    - `GET /api/state/backup?scope=...`
    - `POST /api/state/restore`
    - `POST /api/admin/access-log`
    - `POST /api/auth/request-reset`
    - `POST /api/auth/reset`
    - `GET /api/analytics/dashboard?scope=...`
    - `GET /api/quality/report?scope=...`
    - `POST /api/leads/auto-assign`
  - AES-256-GCM encryption before saving payload to DB
  - Rate limiting + security headers
  - Login lockout controls (failed-attempt protection)
  - Normalized reporting tables for users, leads, appointments, JFA/FA registers
  - Automatic cleanup of used/expired reset tokens
- `docker-compose.yml`
  - `db` (PostgreSQL)
  - `api` (Node/Express secure API)
- `backend/Dockerfile`
- `backend/package.json`
- `backend/.env.example`

## Quick start (Docker)

1. Copy `backend/.env.example` to `backend/.env` (already created in this workspace).
2. Edit `backend/.env` and set:
   - `API_TOKEN`
   - `APP_DATA_KEY` (must be a valid 32-byte key)
   - `APP_PUBLIC_URL`
   - SMTP settings: `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`
   - Optional: `MAX_PAYLOAD_BYTES` (default `10485760`)
   - Recommended security:
     - `ENFORCE_SIGNED_ROLE=true`
     - `LOGIN_MAX_FAILED_ATTEMPTS=8`
     - `LOGIN_LOCKOUT_MINUTES=15`
3. If you changed DB credentials, keep `DATABASE_URL` in `backend/.env` aligned with DB credentials in `docker-compose.yml`.
4. Ensure `JFA_Register.html` uses matching token in:
   - `window.JFA_API_TOKEN`
5. Run:
   - `docker compose up --build -d`
6. Open:
   - `http://localhost:8080/JFA_Register.html`

## Generate encryption key

Use a 32-byte random key (base64):

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

Paste it into `APP_DATA_KEY`.

## Security notes

- The API token in frontend JS is a shared client token; rotate it regularly.
- For stronger security later, move to user-based auth (JWT/session) and role-based API permissions.
- DB payload is encrypted server-side before insert, so raw records in PostgreSQL are not plain JSON.
- Admin (All) access attempts are recorded in `admin_access_log` (username, scope, timestamp, source, IP, user-agent).
