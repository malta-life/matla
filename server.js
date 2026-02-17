import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import bcrypt from 'bcryptjs';
import dotenv from 'dotenv';
import cors from 'cors';
import express from 'express';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, '..');

const PORT = Number(process.env.PORT || 8080);
const DATABASE_URL = (process.env.DATABASE_URL || '').trim();
const API_TOKEN = (process.env.API_TOKEN || '').trim();
const APP_DATA_KEY_RAW = (process.env.APP_DATA_KEY || '').trim();
const ALLOWED_ORIGIN = (process.env.ALLOWED_ORIGIN || '*').trim();
const SERVE_STATIC = (process.env.SERVE_STATIC || 'false').toLowerCase() === 'true';
const STATIC_DIR = process.env.STATIC_DIR
  ? path.resolve(process.env.STATIC_DIR)
  : backendRoot;
const SMTP_HOST = (process.env.SMTP_HOST || '').trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 587);
const SMTP_SECURE = (process.env.SMTP_SECURE || 'false').toLowerCase() === 'true';
const SMTP_USER = (process.env.SMTP_USER || '').trim();
const SMTP_PASS = (process.env.SMTP_PASS || '').trim();
const SMTP_FROM = (process.env.SMTP_FROM || '').trim();
const SMTP_REPLY_TO = (process.env.SMTP_REPLY_TO || '').trim();
const APP_PUBLIC_URL = (process.env.APP_PUBLIC_URL || '').trim();
const APP_RESET_PATH = (process.env.APP_RESET_PATH || '/Daily-Ops.html').trim();
const MAX_PAYLOAD_BYTES = Number(process.env.MAX_PAYLOAD_BYTES || 10 * 1024 * 1024);
const APP_BACKUP_INTERVAL_MINUTES = Math.max(5, Number(process.env.APP_BACKUP_INTERVAL_MINUTES || 60));
const APP_BACKUP_RETENTION_DAYS = Math.max(1, Number(process.env.APP_BACKUP_RETENTION_DAYS || 30));
const APP_AUDIT_RETENTION_DAYS = Math.max(7, Number(process.env.APP_AUDIT_RETENTION_DAYS || 180));
const SESSION_JWT_SECRET = (process.env.SESSION_JWT_SECRET || APP_DATA_KEY_RAW).trim();
const SESSION_TOKEN_TTL_SECONDS = Math.max(300, Number(process.env.SESSION_TOKEN_TTL_SECONDS || 8 * 60 * 60));
const SESSION_REFRESH_TTL_SECONDS = Math.max(
  SESSION_TOKEN_TTL_SECONDS,
  Number(process.env.SESSION_REFRESH_TOKEN_TTL_SECONDS || 14 * 24 * 60 * 60)
);
const SESSION_IDLE_TIMEOUT_SECONDS = Math.max(300, Number(process.env.SESSION_IDLE_TIMEOUT_SECONDS || 12 * 60 * 60));
const ENFORCE_SIGNED_ROLE = (process.env.ENFORCE_SIGNED_ROLE || 'false').toLowerCase() === 'true';
const REQUIRE_2FA_FOR_PRIVILEGED = (process.env.REQUIRE_2FA_FOR_PRIVILEGED || 'false').toLowerCase() === 'true';
const TOTP_WINDOW_STEPS = Math.max(0, Math.min(4, Number(process.env.TOTP_WINDOW_STEPS || 1)));
const LOGIN_MAX_FAILED_ATTEMPTS = Math.max(3, Number(process.env.LOGIN_MAX_FAILED_ATTEMPTS || 8));
const LOGIN_LOCKOUT_MINUTES = Math.max(5, Number(process.env.LOGIN_LOCKOUT_MINUTES || 15));
const SMTP_QUEUE_RETRY_LIMIT = Math.max(1, Number(process.env.SMTP_QUEUE_RETRY_LIMIT || 5));
const SMTP_QUEUE_BATCH_SIZE = Math.max(1, Number(process.env.SMTP_QUEUE_BATCH_SIZE || 20));
const FA_ASSIGN_MAX_PENDING_PER_FA = Math.max(1, Number(process.env.FA_ASSIGN_MAX_PENDING_PER_FA || 60));
const LEAD_ASSIGN_SLA_HOURS = Math.max(1, Number(process.env.LEAD_ASSIGN_SLA_HOURS || 24));

if (!DATABASE_URL) {
  throw new Error('DATABASE_URL is required.');
}
if (!APP_DATA_KEY_RAW) {
  throw new Error('APP_DATA_KEY is required (32-byte key in base64, hex, or plain text length 32).');
}
if (!SMTP_HOST || !SMTP_FROM || !APP_PUBLIC_URL) {
  // Allow API to run without email, but reset flow will be disabled.
  // eslint-disable-next-line no-console
  console.warn('SMTP or APP_PUBLIC_URL not configured; password reset emails will be disabled.');
}

function parseDataKey(input) {
  const trimmed = input.trim();
  if (/^[A-Fa-f0-9]{64}$/.test(trimmed)) return Buffer.from(trimmed, 'hex');
  if (/^[A-Za-z0-9+/=]+$/.test(trimmed)) {
    try {
      const decoded = Buffer.from(trimmed, 'base64');
      if (decoded.length === 32) return decoded;
    } catch (_) {
      // ignore
    }
  }
  const raw = Buffer.from(trimmed, 'utf8');
  if (raw.length === 32) return raw;
  throw new Error('APP_DATA_KEY must decode to exactly 32 bytes.');
}

const APP_DATA_KEY = parseDataKey(APP_DATA_KEY_RAW);
const SESSION_SIGNING_KEY = crypto.createHash('sha256').update(SESSION_JWT_SECRET, 'utf8').digest();
const pool = new Pool({ connectionString: DATABASE_URL });
const mailer = SMTP_HOST
  ? nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      auth: SMTP_USER && SMTP_PASS ? { user: SMTP_USER, pass: SMTP_PASS } : undefined
    })
  : null;

function isResetEmailConfigured() {
  return Boolean(mailer && SMTP_FROM && APP_PUBLIC_URL);
}

function isSafeScope(scope) {
  return typeof scope === 'string' && /^[A-Za-z0-9._:-]{1,120}$/.test(scope);
}

function isSafeUsername(username) {
  return typeof username === 'string' && /^[A-Za-z0-9._@ -]{2,80}$/.test(username.trim());
}

function base64UrlEncode(input) {
  const buffer = Buffer.isBuffer(input) ? input : Buffer.from(String(input || ''), 'utf8');
  return buffer.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(value) {
  const raw = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const padding = raw.length % 4 === 0 ? '' : '='.repeat(4 - (raw.length % 4));
  return Buffer.from(`${raw}${padding}`, 'base64');
}

function signSessionToken(payload) {
  const header = base64UrlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64UrlEncode(JSON.stringify(payload || {}));
  const data = `${header}.${body}`;
  const signature = crypto.createHmac('sha256', SESSION_SIGNING_KEY).update(data, 'utf8').digest();
  return `${data}.${base64UrlEncode(signature)}`;
}

function verifySessionToken(token) {
  const raw = String(token || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;
  const data = `${headerB64}.${payloadB64}`;
  const expected = crypto.createHmac('sha256', SESSION_SIGNING_KEY).update(data, 'utf8').digest();
  const provided = base64UrlDecode(sigB64);
  if (provided.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(provided, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch (_) {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  if (!payload.exp || Number.isNaN(Number(payload.exp))) return null;
  if (Math.floor(Date.now() / 1000) >= Number(payload.exp)) return null;
  return payload;
}

function generateTotpSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(20);
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }
  return output;
}

function decodeBase32(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(secret || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];
  for (const ch of clean) {
    const idx = alphabet.indexOf(ch);
    if (idx < 0) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpCode(secret, timestampMs = Date.now(), stepSeconds = 30, digits = 6) {
  const key = decodeBase32(secret);
  if (!key.length) return '';
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  const counterBuffer = Buffer.alloc(8);
  const high = Math.floor(counter / 0x100000000);
  const low = counter % 0x100000000;
  counterBuffer.writeUInt32BE(high >>> 0, 0);
  counterBuffer.writeUInt32BE(low >>> 0, 4);
  const digest = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  const otp = binary % (10 ** digits);
  return String(otp).padStart(digits, '0');
}

function verifyTotpCode(secret, code, windowSteps = TOTP_WINDOW_STEPS) {
  const normalized = String(code || '').replace(/\s+/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  const now = Date.now();
  for (let drift = -windowSteps; drift <= windowSteps; drift += 1) {
    const candidate = generateTotpCode(secret, now + drift * 30000);
    if (!candidate) continue;
    const a = Buffer.from(candidate, 'utf8');
    const b = Buffer.from(normalized, 'utf8');
    if (a.length === b.length && crypto.timingSafeEqual(a, b)) return true;
  }
  return false;
}

function validateStrongPassword(password) {
  const value = String(password || '');
  if (value.length < 8) return { ok: false, message: 'Password must be at least 8 characters.' };
  if (!/[a-z]/.test(value)) return { ok: false, message: 'Password must include a lowercase letter.' };
  if (!/[A-Z]/.test(value)) return { ok: false, message: 'Password must include an uppercase letter.' };
  if (!/[0-9]/.test(value)) return { ok: false, message: 'Password must include a number.' };
  if (!/[^A-Za-z0-9]/.test(value)) return { ok: false, message: 'Password must include a special character.' };
  return { ok: true };
}

function estimatePayloadBytes(payload) {
  try {
    return Buffer.byteLength(JSON.stringify(payload), 'utf8');
  } catch (_) {
    return Number.POSITIVE_INFINITY;
  }
}

function parseJsonSafely(rawValue, fallback = null) {
  if (typeof rawValue !== 'string') return fallback;
  try {
    return JSON.parse(rawValue);
  } catch (_) {
    return fallback;
  }
}

function validateLeadRecordsPayload(payload) {
  if (!Object.prototype.hasOwnProperty.call(payload, 'leadRecords')) {
    return { ok: true };
  }
  const leadRecordsRaw = payload.leadRecords;
  if (typeof leadRecordsRaw !== 'string') {
    return { ok: false, message: 'leadRecords must be a JSON string.' };
  }
  const leadRecords = parseJsonSafely(leadRecordsRaw, null);
  if (!Array.isArray(leadRecords)) {
    return { ok: false, message: 'leadRecords must decode to an array.' };
  }
  if (leadRecords.length > 100000) {
    return { ok: false, message: 'leadRecords exceeds safe limit.' };
  }

  const seenIds = new Set();
  const seenLeadIds = new Set();
  const allowedLeadStatuses = new Set(['New', 'Contacted', 'Quote', 'Closed', 'Lost']);
  const allowedPaymentStatuses = new Set(['Pending', 'Unsuccessful', 'Successful']);

  for (let index = 0; index < leadRecords.length; index += 1) {
    const lead = leadRecords[index];
    if (!lead || typeof lead !== 'object' || Array.isArray(lead)) {
      return { ok: false, message: `leadRecords[${index}] must be an object.` };
    }
    const recordId = String(lead.id || '').trim();
    const leadId = String(lead.leadId || '').trim().toUpperCase();
    if (!recordId) {
      return { ok: false, message: `leadRecords[${index}] is missing id.` };
    }
    if (!leadId) {
      return { ok: false, message: `leadRecords[${index}] is missing leadId.` };
    }
    if (seenIds.has(recordId)) {
      return { ok: false, message: `Duplicate lead record id detected: ${recordId}` };
    }
    if (seenLeadIds.has(leadId)) {
      return { ok: false, message: `Duplicate leadId detected: ${leadId}` };
    }
    seenIds.add(recordId);
    seenLeadIds.add(leadId);

    const leadStatus = String(lead.status || '').trim();
    if (leadStatus && !allowedLeadStatuses.has(leadStatus)) {
      return { ok: false, message: `Invalid lead status for leadId ${leadId}.` };
    }
    const paymentStatus = String(lead.paymentStatus || '').trim();
    if (paymentStatus && !allowedPaymentStatuses.has(paymentStatus)) {
      return { ok: false, message: `Invalid payment status for leadId ${leadId}.` };
    }

    const timestampRaw = String(lead.timestamp || '').trim();
    if (timestampRaw && Number.isNaN(new Date(timestampRaw).getTime())) {
      return { ok: false, message: `Invalid timestamp for leadId ${leadId}.` };
    }
  }

  return { ok: true };
}

function validateUserAccountsPayload(payload) {
  if (!Object.prototype.hasOwnProperty.call(payload, 'jfaUserAccounts')) {
    return { ok: true };
  }
  const accountsRaw = payload.jfaUserAccounts;
  if (typeof accountsRaw !== 'string') {
    return { ok: false, message: 'jfaUserAccounts must be a JSON string.' };
  }
  const accounts = parseJsonSafely(accountsRaw, null);
  if (!accounts || typeof accounts !== 'object' || Array.isArray(accounts)) {
    return { ok: false, message: 'jfaUserAccounts must decode to an object.' };
  }
  const seenEmails = new Set();
  for (const [key, account] of Object.entries(accounts)) {
    if (!account || typeof account !== 'object' || Array.isArray(account)) {
      return { ok: false, message: `Invalid account record for ${key}.` };
    }
    const username = String(account.username || key || '').trim();
    if (!isSafeUsername(username)) {
      return { ok: false, message: `Invalid username for account ${key}.` };
    }
    const email = String(account.email || '').trim().toLowerCase();
    if (email) {
      if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
        return { ok: false, message: `Invalid email for account ${username}.` };
      }
      if (seenEmails.has(email)) {
        return { ok: false, message: `Duplicate account email detected: ${email}` };
      }
      seenEmails.add(email);
    }
  }
  return { ok: true };
}

function validateStatePayloadShape(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, message: 'Invalid payload' };
  }
  const keys = Object.keys(payload);
  if (keys.length > 400) {
    return { ok: false, message: 'Payload contains too many keys.' };
  }
  const leadValidation = validateLeadRecordsPayload(payload);
  if (!leadValidation.ok) return leadValidation;
  const accountValidation = validateUserAccountsPayload(payload);
  if (!accountValidation.ok) return accountValidation;
  return { ok: true };
}

function sanitizeScope(scopeInput) {
  return (scopeInput || '').toString().trim();
}

function sanitizeRole(roleInput) {
  const role = String(roleInput || '').trim().toUpperCase();
  if (role === 'ADMIN' || role === 'TEAM' || role === 'PERSONAL') return role;
  return 'PERSONAL';
}

function sanitizeActor(actorInput) {
  return String(actorInput || '').trim().slice(0, 120) || 'unknown';
}

function getActorContext(req) {
  if (req?.authContext && req.authContext.type === 'signed') {
    return {
      role: sanitizeRole(req.authContext.role),
      actor: sanitizeActor(req.authContext.actor || req.authContext.username),
      sessionId: sanitizeActor(req.authContext.sessionId)
    };
  }
  const role = sanitizeRole(req.get('x-app-role') || req.body?.actorRole);
  const actor = sanitizeActor(req.get('x-app-user') || req.body?.actor || req.body?.username);
  const sessionId = sanitizeActor(req.get('x-app-session'));
  return { role, actor, sessionId };
}

function hasAdminRole(req) {
  if (ENFORCE_SIGNED_ROLE && req?.authContext?.type !== 'signed') return false;
  return getActorContext(req).role === 'ADMIN';
}

function isEncryptedBackupShape(value) {
  if (!value || typeof value !== 'object') return false;
  const payloadEncB64 = String(value.payloadEncB64 || '').trim();
  const ivB64 = String(value.ivB64 || '').trim();
  const tagB64 = String(value.tagB64 || '').trim();
  if (!payloadEncB64 || !ivB64 || !tagB64) return false;
  return /^[A-Za-z0-9+/=]+$/.test(payloadEncB64)
    && /^[A-Za-z0-9+/=]+$/.test(ivB64)
    && /^[A-Za-z0-9+/=]+$/.test(tagB64);
}

function authMiddleware(req, res, next) {
  req.authContext = null;
  const auth = req.get('authorization') || '';
  const prefix = 'Bearer ';
  if (!API_TOKEN && !auth.startsWith(prefix)) return next();
  if (!auth.startsWith(prefix)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const provided = auth.slice(prefix.length).trim();
  if (!provided) return res.status(401).json({ error: 'Unauthorized' });
  const signed = verifySessionToken(provided);
  if (signed) {
    req.authContext = {
      type: 'signed',
      role: sanitizeRole(signed.role),
      actor: sanitizeActor(signed.actor || signed.username),
      username: sanitizeActor(signed.username),
      userKey: normalizeKey(signed.userKey || signed.sub || ''),
      scope: sanitizeScope(signed.scope),
      sessionId: sanitizeActor(signed.sessionId || ''),
      mfa: signed.mfa === true
    };
    return next();
  }
  if (!API_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const expected = API_TOKEN;
  const providedBuf = Buffer.from(provided, 'utf8');
  const expectedBuf = Buffer.from(expected, 'utf8');
  if (providedBuf.length !== expectedBuf.length) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  if (!crypto.timingSafeEqual(providedBuf, expectedBuf)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.authContext = { type: 'legacy-token' };
  return next();
}

function endpointAccessPolicyMiddleware(req, res, next) {
  const policy = getEndpointPolicy(req);
  if (!policy) return next();
  if (policy.requireSigned && !isSignedSession(req)) {
    return res.status(401).json({ error: 'Signed session required' });
  }
  if (policy.roles && policy.roles.length && !hasAnyRole(req, policy.roles)) {
    return res.status(403).json({ error: 'Role not allowed for this endpoint' });
  }

  const requestScope = getRequestScope(req);
  const tokenScope = sanitizeScope(req?.authContext?.scope);
  const role = sanitizeRole(req?.authContext?.role);
  if (isSignedSession(req) && requestScope && tokenScope && requestScope !== tokenScope && role !== 'ADMIN') {
    return res.status(403).json({ error: 'Scope mismatch for signed session' });
  }

  const requestedTeam = String(req?.body?.team || req?.query?.team || '').trim();
  const tokenTeam = getTokenTeam(req);
  if (role === 'TEAM' && requestedTeam && tokenTeam && requestedTeam !== tokenTeam) {
    return res.status(403).json({ error: 'Team scope mismatch' });
  }
  return next();
}

function getEffectiveRole(req) {
  return getActorContext(req).role;
}

function hasAnyRole(req, roles = []) {
  if (ENFORCE_SIGNED_ROLE && req?.authContext?.type !== 'signed') return false;
  const allowed = new Set((roles || []).map((role) => sanitizeRole(role)));
  return allowed.has(getEffectiveRole(req));
}

function getRequestScope(req) {
  const scopeFromBody = sanitizeScope(req?.body?.scope);
  const scopeFromQuery = sanitizeScope(req?.query?.scope);
  return scopeFromBody || scopeFromQuery || '';
}

function isSignedSession(req) {
  return req?.authContext?.type === 'signed';
}

function getTokenTeam(req) {
  return String(req?.authContext?.team || '').trim();
}

const ENDPOINT_ROLE_POLICIES = [
  { method: 'GET', path: '/api/metrics', roles: ['ADMIN'], requireSigned: true },
  { method: 'GET', path: '/api/state/snapshots', roles: ['ADMIN'], requireSigned: true },
  { method: 'GET', path: '/api/state/backup', roles: ['ADMIN'], requireSigned: true },
  { method: 'POST', path: '/api/state/restore', roles: ['ADMIN'], requireSigned: true },
  { method: 'POST', path: '/api/admin/access-log', roles: ['ADMIN', 'TEAM'], requireSigned: true },
  { method: 'POST', path: '/api/audit/append', roles: ['ADMIN', 'TEAM'], requireSigned: true },
  { method: 'GET', path: '/api/audit/integrity', roles: ['ADMIN'], requireSigned: true },
  { method: 'GET', path: '/api/analytics/dashboard', roles: ['ADMIN', 'TEAM'], requireSigned: true },
  { method: 'GET', path: '/api/quality/report', roles: ['ADMIN', 'TEAM'], requireSigned: true },
  { method: 'GET', path: '/api/sensitive', roles: ['ADMIN'], requireSigned: true },
  { method: 'POST', path: '/api/leads/auto-assign', roles: ['ADMIN', 'TEAM'], requireSigned: true },
  { method: 'GET', path: '/api/leads/assignment-board', roles: ['ADMIN', 'TEAM'], requireSigned: true },
  { method: 'GET', path: '/api/reminders/list', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true },
  { method: 'GET', path: '/api/auth/session', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true },
  { method: 'POST', path: '/api/auth/refresh', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: false },
  { method: 'POST', path: '/api/auth/logout', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true },
  { method: 'GET', path: '/api/auth/sessions', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true },
  { method: 'DELETE', path: '/api/auth/sessions', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true },
  { method: 'POST', path: '/api/state/save', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true },
  { method: 'GET', path: '/api/state/load', roles: ['ADMIN', 'TEAM', 'PERSONAL'], requireSigned: true }
];

function getEndpointPolicy(req) {
  const method = String(req.method || '').toUpperCase();
  const reqPath = String(req.path || '');
  return ENDPOINT_ROLE_POLICIES.find((policy) => {
    if (policy.method !== method) return false;
    if (policy.path === reqPath) return true;
    if (policy.path === '/api/auth/sessions' && reqPath.startsWith('/api/auth/sessions/')) return true;
    if (policy.path === '/api/sensitive' && reqPath.startsWith('/api/sensitive/')) return true;
    return false;
  }) || null;
}

function encryptPayload(payloadObj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', APP_DATA_KEY, iv);
  const raw = Buffer.from(JSON.stringify(payloadObj), 'utf8');
  const encrypted = Buffer.concat([cipher.update(raw), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    payloadEnc: encrypted.toString('base64'),
    iv: iv.toString('base64'),
    tag: tag.toString('base64')
  };
}

function decryptPayload(row) {
  const iv = Buffer.from(row.iv_b64, 'base64');
  const tag = Buffer.from(row.tag_b64, 'base64');
  const encrypted = Buffer.from(row.payload_enc_b64, 'base64');
  const decipher = crypto.createDecipheriv('aes-256-gcm', APP_DATA_KEY, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return JSON.parse(decrypted.toString('utf8'));
}

function encryptSensitiveObject(payloadObj) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', APP_DATA_KEY, iv);
  const raw = Buffer.from(JSON.stringify(payloadObj || {}), 'utf8');
  const encrypted = Buffer.concat([cipher.update(raw), cipher.final()]);
  const tag = cipher.getAuthTag();
  return {
    payloadEncB64: encrypted.toString('base64'),
    ivB64: iv.toString('base64'),
    tagB64: tag.toString('base64')
  };
}

async function ensureSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state (
      scope TEXT PRIMARY KEY,
      payload_enc_b64 TEXT NOT NULL,
      iv_b64 TEXT NOT NULL,
      tag_b64 TEXT NOT NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admin_access_log (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      username TEXT NOT NULL,
      section TEXT NOT NULL,
      role TEXT NOT NULL,
      source TEXT NOT NULL,
      user_agent TEXT NOT NULL DEFAULT '',
      ip_address TEXT NOT NULL DEFAULT '',
      happened_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_admin_access_log_scope_happened
    ON admin_access_log (scope, happened_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      account_key TEXT NOT NULL,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      used_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_scope_token
    ON password_reset_tokens (scope, token_hash);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS immutable_audit_log (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      actor TEXT NOT NULL,
      actor_role TEXT NOT NULL,
      session_id TEXT NOT NULL DEFAULT '',
      action TEXT NOT NULL,
      details TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT 'web',
      ip_address TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    ALTER TABLE immutable_audit_log
    ADD COLUMN IF NOT EXISTS entry_hash TEXT,
    ADD COLUMN IF NOT EXISTS prev_hash TEXT;
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_immutable_audit_scope_created
    ON immutable_audit_log (scope, created_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS app_state_snapshots (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      payload_enc_b64 TEXT NOT NULL,
      iv_b64 TEXT NOT NULL,
      tag_b64 TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT 'scheduled',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_app_state_snapshots_scope_created
    ON app_state_snapshots (scope, created_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reminder_events (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      user_key TEXT NOT NULL,
      reminder_type TEXT NOT NULL,
      reminder_key TEXT NOT NULL,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      due_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      delivered_at TIMESTAMPTZ NULL,
      UNIQUE (scope, user_key, reminder_key)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_reminder_events_scope_user_due
    ON reminder_events (scope, user_key, due_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_login_attempts (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      identity_key TEXT NOT NULL,
      ip_address TEXT NOT NULL DEFAULT '',
      attempt_count INT NOT NULL DEFAULT 0,
      locked_until TIMESTAMPTZ NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE (scope, identity_key, ip_address)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_auth_login_attempts_scope_identity
    ON auth_login_attempts (scope, identity_key, updated_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS auth_sessions (
      scope TEXT NOT NULL,
      session_id TEXT NOT NULL,
      user_key TEXT NOT NULL,
      username TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL DEFAULT 'PERSONAL',
      team TEXT NOT NULL DEFAULT '',
      ip_address TEXT NOT NULL DEFAULT '',
      user_agent TEXT NOT NULL DEFAULT '',
      refresh_token_hash TEXT NOT NULL DEFAULT '',
      mfa BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expires_at TIMESTAMPTZ NOT NULL,
      revoked_at TIMESTAMPTZ NULL,
      revoke_reason TEXT NOT NULL DEFAULT '',
      PRIMARY KEY (scope, session_id)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_auth_sessions_scope_user_active
    ON auth_sessions (scope, user_key, revoked_at, expires_at DESC, last_seen_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS smtp_outbox (
      id BIGSERIAL PRIMARY KEY,
      scope TEXT NOT NULL,
      template TEXT NOT NULL,
      to_email TEXT NOT NULL,
      payload_json TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending',
      attempts INT NOT NULL DEFAULT 0,
      next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_error TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      sent_at TIMESTAMPTZ NULL
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_smtp_outbox_dispatch
    ON smtp_outbox (status, next_attempt_at ASC, created_at ASC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS normalized_users (
      scope TEXT NOT NULL,
      user_key TEXT NOT NULL,
      username TEXT NOT NULL,
      email TEXT NOT NULL DEFAULT '',
      role TEXT NOT NULL,
      team TEXT NOT NULL DEFAULT '',
      is_active BOOLEAN NOT NULL DEFAULT true,
      source TEXT NOT NULL DEFAULT 'JFA',
      last_seen_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, user_key)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_normalized_users_scope_role_team
    ON normalized_users (scope, role, team);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS normalized_jfa_register (
      scope TEXT NOT NULL,
      record_id TEXT NOT NULL,
      user_key TEXT NOT NULL,
      full_name TEXT NOT NULL,
      team TEXT NOT NULL DEFAULT '',
      facility_name TEXT NOT NULL DEFAULT '',
      productive TEXT NOT NULL DEFAULT '',
      consent_forms INT NOT NULL DEFAULT 0,
      present BOOLEAN NOT NULL DEFAULT true,
      record_date DATE NOT NULL,
      submitted_at TIMESTAMPTZ NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, record_id)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_normalized_jfa_register_scope_date_team
    ON normalized_jfa_register (scope, record_date DESC, team);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS normalized_fa_register (
      scope TEXT NOT NULL,
      user_key TEXT NOT NULL,
      full_name TEXT NOT NULL,
      username TEXT NOT NULL,
      team TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'Active',
      is_active BOOLEAN NOT NULL DEFAULT true,
      phone_masked TEXT NOT NULL DEFAULT '',
      email TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, user_key)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_normalized_fa_register_scope_team_active
    ON normalized_fa_register (scope, team, is_active);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS normalized_leads (
      scope TEXT NOT NULL,
      lead_id TEXT NOT NULL,
      record_id TEXT NOT NULL,
      jfa_user_key TEXT NOT NULL,
      jfa_name TEXT NOT NULL,
      jfa_team TEXT NOT NULL DEFAULT '',
      client_name TEXT NOT NULL DEFAULT '',
      client_surname TEXT NOT NULL DEFAULT '',
      client_id_hash TEXT NOT NULL DEFAULT '',
      client_phone_masked TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL DEFAULT 'New',
      payment_status TEXT NOT NULL DEFAULT 'Pending',
      failure_reason TEXT NOT NULL DEFAULT '',
      commission_date TEXT NOT NULL DEFAULT '',
      product TEXT NOT NULL DEFAULT '',
      facility_name TEXT NOT NULL DEFAULT '',
      has_signature BOOLEAN NOT NULL DEFAULT false,
      has_geotag BOOLEAN NOT NULL DEFAULT false,
      geo_lat DOUBLE PRECISION NULL,
      geo_lng DOUBLE PRECISION NULL,
      fa_assigned_user_key TEXT NOT NULL DEFAULT '',
      fa_assigned_name TEXT NOT NULL DEFAULT '',
      fa_assigned_at TIMESTAMPTZ NULL,
      route_reason TEXT NOT NULL DEFAULT '',
      lead_date DATE NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, lead_id)
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS lead_id_registry (
      scope TEXT NOT NULL,
      lead_id TEXT NOT NULL,
      record_id TEXT NOT NULL,
      first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, lead_id)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_lead_id_registry_scope_seen
    ON lead_id_registry (scope, first_seen_at DESC, last_seen_at DESC);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_normalized_leads_scope_status_payment
    ON normalized_leads (scope, status, payment_status, lead_date DESC);
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_normalized_leads_scope_team
    ON normalized_leads (scope, jfa_team, lead_date DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS encrypted_sensitive_store (
      scope TEXT NOT NULL,
      record_type TEXT NOT NULL,
      record_key TEXT NOT NULL,
      payload_enc_b64 TEXT NOT NULL,
      iv_b64 TEXT NOT NULL,
      tag_b64 TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, record_type, record_key)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_encrypted_sensitive_store_scope_type
    ON encrypted_sensitive_store (scope, record_type, updated_at DESC);
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS normalized_appointments (
      scope TEXT NOT NULL,
      appointment_id TEXT NOT NULL,
      lead_id TEXT NOT NULL DEFAULT '',
      user_key TEXT NOT NULL,
      team TEXT NOT NULL DEFAULT '',
      client_name TEXT NOT NULL DEFAULT '',
      client_phone_masked TEXT NOT NULL DEFAULT '',
      appointment_at TIMESTAMPTZ NOT NULL,
      status TEXT NOT NULL DEFAULT 'Scheduled',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      PRIMARY KEY (scope, appointment_id)
    );
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_normalized_appointments_scope_when
    ON normalized_appointments (scope, appointment_at DESC, team);
  `);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token, 'utf8').digest('hex');
}

function createPasswordRecord(password) {
  const value = String(password || '');
  const bcryptHash = bcrypt.hashSync(value, 12);
  const salt = crypto.randomBytes(16).toString('base64');
  const hash = crypto
    .createHash('sha256')
    .update(`${salt}:${value}`, 'utf8')
    .digest('base64');
  return { salt, hash, bcryptHash };
}

async function loadAppState(scope) {
  const result = await pool.query(
    `SELECT scope, payload_enc_b64, iv_b64, tag_b64, updated_at FROM app_state WHERE scope = $1`,
    [scope]
  );
  if (!result.rows.length) return { scope, payload: {}, updatedAt: null };
  const row = result.rows[0];
  const payload = decryptPayload(row);
  return { scope, payload, updatedAt: row.updated_at };
}

async function saveAppState(scope, payload) {
  const encrypted = encryptPayload(payload);
  const result = await pool.query(
    `
    INSERT INTO app_state (scope, payload_enc_b64, iv_b64, tag_b64, updated_at)
    VALUES ($1, $2, $3, $4, NOW())
    ON CONFLICT (scope)
    DO UPDATE SET
      payload_enc_b64 = EXCLUDED.payload_enc_b64,
      iv_b64 = EXCLUDED.iv_b64,
      tag_b64 = EXCLUDED.tag_b64,
      updated_at = NOW()
    RETURNING updated_at
    `,
    [scope, encrypted.payloadEnc, encrypted.iv, encrypted.tag]
  );
  await syncNormalizedState(scope, payload);
  return result.rows[0]?.updated_at || new Date().toISOString();
}

async function appendImmutableAudit({
  scope,
  actor = 'unknown',
  actorRole = 'PERSONAL',
  sessionId = '',
  action,
  details = '',
  source = 'web',
  ipAddress = '',
  userAgent = ''
}) {
  const safeScope = sanitizeScope(scope);
  if (!isSafeScope(safeScope)) return;
  const safeActor = sanitizeActor(actor);
  const safeRole = sanitizeRole(actorRole);
  const safeSession = sanitizeActor(sessionId);
  const safeAction = String(action || '').trim().slice(0, 120);
  if (!safeAction) return;
  const safeDetails = String(details || '').slice(0, 4000);
  const safeSource = String(source || 'web').slice(0, 40);
  const safeIp = String(ipAddress || '').slice(0, 120);
  const safeUa = String(userAgent || '').slice(0, 800);
  const prev = await pool.query(
    `SELECT entry_hash FROM immutable_audit_log WHERE scope = $1 ORDER BY id DESC LIMIT 1`,
    [safeScope]
  );
  const prevHash = String(prev.rows[0]?.entry_hash || '');
  const entryHash = crypto.createHash('sha256').update(
    `${safeScope}|${safeActor}|${safeRole}|${safeSession}|${safeAction}|${safeDetails}|${safeSource}|${safeIp}|${safeUa}|${prevHash}`,
    'utf8'
  ).digest('hex');
  await pool.query(
    `
    INSERT INTO immutable_audit_log
      (scope, actor, actor_role, session_id, action, details, source, ip_address, user_agent, entry_hash, prev_hash)
    VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `,
    [
      safeScope,
      safeActor,
      safeRole,
      safeSession,
      safeAction,
      safeDetails,
      safeSource,
      safeIp,
      safeUa,
      entryHash,
      prevHash
    ]
  );
}

function getRequestMeta(req) {
  const forwarded = (req.headers['x-forwarded-for'] || '').toString().split(',')[0] || '';
  const ipAddress = (forwarded || req.ip || '').toString().slice(0, 120);
  const userAgent = (req.get('user-agent') || '').toString().slice(0, 800);
  return { ipAddress, userAgent };
}

function parsePayloadJson(payload, key, fallback) {
  if (!payload || typeof payload !== 'object') return fallback;
  const raw = payload[key];
  if (raw && typeof raw === 'object') return raw;
  if (typeof raw !== 'string' || !raw.trim()) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : fallback;
  } catch (_) {
    return fallback;
  }
}

function writePayloadJson(payload, key, value) {
  payload[key] = JSON.stringify(value);
}

function parsePayloadArray(payload, key) {
  const parsed = parsePayloadJson(payload, key, []);
  return Array.isArray(parsed) ? parsed : [];
}

function parsePayloadObject(payload, key) {
  const parsed = parsePayloadJson(payload, key, {});
  return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
}

function normalizePhone(value) {
  return String(value || '').replace(/\D+/g, '').slice(0, 20);
}

function parseIsoDate(input) {
  const value = String(input || '').trim();
  if (!value) return null;
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return null;
  return dt.toISOString();
}

function hashClientIdentifier(input) {
  const value = String(input || '').replace(/\s+/g, '').toLowerCase();
  if (!value) return '';
  return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function verifyAccountPassword(account, password) {
  if (!account || typeof account !== 'object') return false;
  const provided = String(password || '');
  if (!provided) return false;
  if (account.passwordHash && String(account.passwordHash).startsWith('$2')) {
    return bcrypt.compareSync(provided, String(account.passwordHash));
  }
  if (account.passwordHash && account.passwordSalt) {
    const computed = crypto
      .createHash('sha256')
      .update(`${account.passwordSalt}:${provided}`, 'utf8')
      .digest('base64');
    const a = Buffer.from(String(account.passwordHash), 'utf8');
    const b = Buffer.from(computed, 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  if (account.password != null) {
    const expected = String(account.password);
    const a = Buffer.from(expected, 'utf8');
    const b = Buffer.from(provided, 'utf8');
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  return false;
}

function determineAccountRole(account, accountKey) {
  const key = normalizeKey(accountKey);
  if (key === 'admin' || account?.adminOnly === true) return 'ADMIN';
  const perms = account?.permissions && typeof account.permissions === 'object' ? account.permissions : {};
  if (perms.admin === true) return account?.team ? 'TEAM' : 'ADMIN';
  return 'PERSONAL';
}

function resolveAccountFromPayload(accounts, identifier) {
  const input = String(identifier || '').trim().toLowerCase();
  if (!input || !accounts || typeof accounts !== 'object') return null;
  for (const [key, account] of Object.entries(accounts)) {
    const username = String(account?.username || key || '').trim().toLowerCase();
    const email = String(account?.email || '').trim().toLowerCase();
    if (input === username || (email && input === email)) {
      return { key: normalizeKey(key), account: account || {} };
    }
  }
  return null;
}

function splitClientName(raw) {
  const clean = String(raw || '').trim().replace(/\s+/g, ' ');
  if (!clean) return { name: '', surname: '' };
  const parts = clean.split(' ');
  if (parts.length === 1) return { name: parts[0], surname: '' };
  return { name: parts[0], surname: parts.slice(1).join(' ') };
}

function safeInt(value, fallback = 0) {
  const num = Number(value);
  if (!Number.isFinite(num)) return fallback;
  return Math.trunc(num);
}

async function getLoginLockState(scope, identityKey, ipAddress) {
  const result = await pool.query(
    `
    SELECT attempt_count, locked_until
    FROM auth_login_attempts
    WHERE scope = $1 AND identity_key = $2 AND ip_address = $3
    LIMIT 1
    `,
    [scope, identityKey, ipAddress]
  );
  if (!result.rows.length) return { attempts: 0, lockedUntil: null, isLocked: false };
  const attempts = safeInt(result.rows[0].attempt_count, 0);
  const lockedUntil = result.rows[0].locked_until ? new Date(result.rows[0].locked_until) : null;
  const isLocked = Boolean(lockedUntil && lockedUntil.getTime() > Date.now());
  return { attempts, lockedUntil, isLocked };
}

async function registerLoginFailure(scope, identityKey, ipAddress) {
  const lockMinutes = LOGIN_LOCKOUT_MINUTES;
  await pool.query(
    `
    INSERT INTO auth_login_attempts
      (scope, identity_key, ip_address, attempt_count, updated_at)
    VALUES
      ($1, $2, $3, 1, NOW())
    ON CONFLICT (scope, identity_key, ip_address)
    DO UPDATE
      SET attempt_count = auth_login_attempts.attempt_count + 1,
          locked_until = CASE
            WHEN (auth_login_attempts.attempt_count + 1) >= $4
              THEN NOW() + ($5::text || ' minutes')::interval
            ELSE auth_login_attempts.locked_until
          END,
          updated_at = NOW()
    `,
    [scope, identityKey, ipAddress, LOGIN_MAX_FAILED_ATTEMPTS, String(lockMinutes)]
  );
}

async function clearLoginFailures(scope, identityKey, ipAddress) {
  await pool.query(
    `
    DELETE FROM auth_login_attempts
    WHERE scope = $1 AND identity_key = $2 AND ip_address = $3
    `,
    [scope, identityKey, ipAddress]
  );
}

async function syncNormalizedState(scope, payload) {
  const accounts = parsePayloadObject(payload, 'jfaUserAccounts');
  const jfaProfiles = parsePayloadObject(payload, 'jfaProfiles');
  const faProfiles = parsePayloadObject(payload, 'faProfiles');
  const jfaRecords = parsePayloadArray(payload, 'jfaRecords');
  const leadRecords = parsePayloadArray(payload, 'leadRecords');
  const appointments = parsePayloadArray(payload, 'jfaAppointments');
  const nowIso = new Date().toISOString();

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM normalized_users WHERE scope = $1', [scope]);
    await client.query('DELETE FROM normalized_jfa_register WHERE scope = $1', [scope]);
    await client.query('DELETE FROM normalized_fa_register WHERE scope = $1', [scope]);
    await client.query('DELETE FROM normalized_leads WHERE scope = $1', [scope]);
    await client.query('DELETE FROM normalized_appointments WHERE scope = $1', [scope]);
    await client.query('DELETE FROM encrypted_sensitive_store WHERE scope = $1', [scope]);

    for (const [key, account] of Object.entries(accounts)) {
      const userKey = normalizeKey(key);
      if (!userKey) continue;
      const username = String(account?.username || key || '').trim() || userKey;
      const email = String(account?.email || '').trim().toLowerCase();
      const role = determineAccountRole(account, userKey);
      const team = String(account?.team || jfaProfiles[userKey]?.team || '').trim();
      const active = account?.active !== false;
      await client.query(
        `
        INSERT INTO normalized_users
          (scope, user_key, username, email, role, team, is_active, source, last_seen_at, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, 'JFA', NULL, NOW(), NOW())
        `,
        [scope, userKey, username, email, role, team, active]
      );
    }

    for (const [key, profile] of Object.entries(faProfiles)) {
      const userKey = normalizeKey(key || profile?.username || profile?.fullName);
      if (!userKey) continue;
      const fullName = String(profile?.fullName || `${profile?.name || ''} ${profile?.surname || ''}`).trim() || userKey;
      const username = String(profile?.username || userKey).trim();
      const team = String(profile?.team || '').trim();
      const status = String(profile?.status || (profile?.active === false ? 'Inactive' : 'Active')).trim();
      const isActive = status.toLowerCase() !== 'inactive' && profile?.active !== false;
      const email = String(profile?.email || '').trim().toLowerCase();
      const phoneMasked = String(profile?.phone || '').trim().replace(/^(\d{3})\d+(\d{2})$/, '$1****$2');
      await client.query(
        `
        INSERT INTO normalized_fa_register
          (scope, user_key, full_name, username, team, status, is_active, phone_masked, email, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        `,
        [scope, userKey, fullName, username, team, status || 'Active', isActive, phoneMasked, email]
      );
      await client.query(
        `
        INSERT INTO normalized_users
          (scope, user_key, username, email, role, team, is_active, source, last_seen_at, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, 'FA', $5, $6, 'FA', NULL, NOW(), NOW())
        ON CONFLICT (scope, user_key)
        DO UPDATE SET
          username = EXCLUDED.username,
          email = EXCLUDED.email,
          role = EXCLUDED.role,
          team = EXCLUDED.team,
          is_active = EXCLUDED.is_active,
          source = EXCLUDED.source,
          updated_at = NOW()
        `,
        [scope, userKey, username, email, team, isActive]
      );
    }

    for (const [key, profile] of Object.entries(jfaProfiles)) {
      const userKey = normalizeKey(key || profile?.fullName || '');
      if (!userKey) continue;
      const encrypted = encryptSensitiveObject({
        type: 'jfa-profile',
        userKey,
        fullName: String(profile?.fullName || '').trim(),
        phone: String(profile?.phone || '').trim(),
        email: String(profile?.email || '').trim().toLowerCase(),
        address: String(profile?.address || '').trim(),
        bankName: String(profile?.bankName || '').trim(),
        accountNumber: String(profile?.accountNumber || '').trim(),
        branchCode: String(profile?.branchCode || '').trim(),
        taxNumber: String(profile?.taxNumber || '').trim(),
        nextOfKinName: String(profile?.nextOfKinName || '').trim(),
        nextOfKinPhone: String(profile?.nextOfKinPhone || '').trim(),
        nextOfKinRelationship: String(profile?.nextOfKinRelationship || '').trim()
      });
      await client.query(
        `
        INSERT INTO encrypted_sensitive_store
          (scope, record_type, record_key, payload_enc_b64, iv_b64, tag_b64, created_at, updated_at)
        VALUES
          ($1, 'jfa-profile', $2, $3, $4, $5, NOW(), NOW())
        `,
        [scope, userKey, encrypted.payloadEncB64, encrypted.ivB64, encrypted.tagB64]
      );
    }

    for (const [key, profile] of Object.entries(faProfiles)) {
      const userKey = normalizeKey(key || profile?.username || '');
      if (!userKey) continue;
      const encrypted = encryptSensitiveObject({
        type: 'fa-profile',
        userKey,
        fullName: String(profile?.fullName || '').trim(),
        phone: String(profile?.phone || '').trim(),
        email: String(profile?.email || '').trim().toLowerCase(),
        address: String(profile?.address || '').trim(),
        bankName: String(profile?.bankName || '').trim(),
        accountNumber: String(profile?.accountNumber || '').trim(),
        branchCode: String(profile?.branchCode || '').trim(),
        taxNumber: String(profile?.taxNumber || '').trim(),
        nextOfKinName: String(profile?.nextOfKinName || '').trim(),
        nextOfKinPhone: String(profile?.nextOfKinPhone || '').trim(),
        nextOfKinRelationship: String(profile?.nextOfKinRelationship || '').trim()
      });
      await client.query(
        `
        INSERT INTO encrypted_sensitive_store
          (scope, record_type, record_key, payload_enc_b64, iv_b64, tag_b64, created_at, updated_at)
        VALUES
          ($1, 'fa-profile', $2, $3, $4, $5, NOW(), NOW())
        `,
        [scope, userKey, encrypted.payloadEncB64, encrypted.ivB64, encrypted.tagB64]
      );
    }

    for (const record of jfaRecords) {
      const recordId = String(record?.id || '').trim() || `${record?.name || 'jfa'}-${record?.timestamp || nowIso}`;
      const fullName = String(record?.name || '').trim() || 'Unknown';
      const userKey = normalizeKey(fullName);
      const team = String(record?.team || '').trim();
      const facilityName = String(record?.facility?.name || record?.facilityName || '').trim();
      const productive = String(record?.productive || '').trim();
      const consentForms = Math.max(0, safeInt(record?.consentForms, 0));
      const submittedAt = parseIsoDate(record?.timestamp);
      const recordDate = submittedAt ? submittedAt.slice(0, 10) : nowIso.slice(0, 10);
      await client.query(
        `
        INSERT INTO normalized_jfa_register
          (scope, record_id, user_key, full_name, team, facility_name, productive, consent_forms, present, record_date, submitted_at, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, true, $9::date, $10, NOW(), NOW())
        `,
        [scope, recordId, userKey, fullName, team, facilityName, productive, consentForms, recordDate, submittedAt]
      );
    }

    for (const lead of leadRecords) {
      const leadId = String(lead?.leadId || '').trim().toUpperCase();
      if (!leadId) continue;
      const recordId = String(lead?.id || leadId).trim();
      const jfaName = String(lead?.jfaName || '').trim();
      const jfaUserKey = normalizeKey(jfaName);
      const team = String(lead?.jfaTeam || '').trim();
      const split = splitClientName(lead?.clientNameRaw || lead?.clientName || '');
      const status = String(lead?.status || 'New').trim() || 'New';
      const paymentStatus = String(lead?.paymentStatus || 'Pending').trim() || 'Pending';
      const failureReason = String(lead?.failureReason || '').trim();
      const commissionDate = String(lead?.commissionDate || '').trim();
      const product = String(lead?.product || '').trim();
      const facilityName = String(lead?.facilityName || lead?.facility?.name || '').trim();
      const hasSignature = Boolean(String(lead?.clientSignatureImage || '').trim());
      const hasGeoTag = Boolean(
        lead?.geo?.coords
        && Number.isFinite(Number(lead.geo.coords.lat))
        && Number.isFinite(Number(lead.geo.coords.lng))
      );
      const geoLat = hasGeoTag ? Number(lead.geo.coords.lat) : null;
      const geoLng = hasGeoTag ? Number(lead.geo.coords.lng) : null;
      const createdAt = parseIsoDate(lead?.timestamp) || nowIso;
      const leadDate = createdAt.slice(0, 10);
      const clientIdHash = hashClientIdentifier(lead?.clientIdRaw || lead?.clientId || '');
      const clientPhoneMasked = String(lead?.clientCell || '').trim();
      const faAssignedKey = normalizeKey(lead?.assignedFaUserKey || '');
      const faAssignedName = String(lead?.assignedFaName || '').trim();
      const faAssignedAt = parseIsoDate(lead?.assignedFaAt);
      const routeReason = String(lead?.routeReason || '').trim();
      const registryResult = await client.query(
        `
        INSERT INTO lead_id_registry
          (scope, lead_id, record_id, first_seen_at, last_seen_at)
        VALUES
          ($1, $2, $3, NOW(), NOW())
        ON CONFLICT (scope, lead_id)
        DO UPDATE SET
          last_seen_at = NOW()
        RETURNING record_id
        `,
        [scope, leadId, recordId]
      );
      const registryRecordId = String(registryResult.rows?.[0]?.record_id || '').trim();
      if (registryRecordId && registryRecordId !== recordId) {
        throw new Error(`Lead ID reuse blocked by registry: ${leadId}`);
      }
      await client.query(
        `
        INSERT INTO normalized_leads
          (scope, lead_id, record_id, jfa_user_key, jfa_name, jfa_team, client_name, client_surname, client_id_hash, client_phone_masked,
           status, payment_status, failure_reason, commission_date, product, facility_name, has_signature, has_geotag, geo_lat, geo_lng,
           fa_assigned_user_key, fa_assigned_name, fa_assigned_at, route_reason, lead_date, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
           $11, $12, $13, $14, $15, $16, $17, $18, $19, $20,
           $21, $22, $23, $24, $25::date, $26, NOW())
        `,
        [
          scope, leadId, recordId, jfaUserKey, jfaName, team, split.name, split.surname, clientIdHash, clientPhoneMasked,
          status, paymentStatus, failureReason, commissionDate, product, facilityName, hasSignature, hasGeoTag, geoLat, geoLng,
          faAssignedKey, faAssignedName, faAssignedAt, routeReason, leadDate, createdAt
        ]
      );
      const encryptedLead = encryptSensitiveObject({
        type: 'lead-client',
        leadId,
        recordId,
        clientNameRaw: String(lead?.clientNameRaw || lead?.clientName || '').trim(),
        clientIdRaw: String(lead?.clientIdRaw || lead?.clientId || '').trim(),
        clientCell: String(lead?.clientCell || '').trim(),
        clientHome: String(lead?.clientHome || '').trim(),
        clientEmail: String(lead?.clientEmail || '').trim().toLowerCase(),
        clientAddress: String(lead?.clientAddress || '').trim(),
        signatureImage: String(lead?.clientSignatureImage || '').trim(),
        geo: lead?.geo && typeof lead.geo === 'object' ? lead.geo : null
      });
      await client.query(
        `
        INSERT INTO encrypted_sensitive_store
          (scope, record_type, record_key, payload_enc_b64, iv_b64, tag_b64, created_at, updated_at)
        VALUES
          ($1, 'lead-client', $2, $3, $4, $5, NOW(), NOW())
        `,
        [scope, leadId, encryptedLead.payloadEncB64, encryptedLead.ivB64, encryptedLead.tagB64]
      );
    }

    for (const appt of appointments) {
      const appointmentId = String(appt?.id || `${appt?.leadId || ''}-${appt?.date || ''}-${appt?.time || ''}`).trim();
      if (!appointmentId) continue;
      const leadId = String(appt?.leadId || '').trim();
      const userKey = normalizeKey(appt?.jfaName || appt?.jfaUsername || '');
      const team = String(appt?.jfaTeam || '').trim();
      const clientName = String(appt?.clientName || '').trim();
      const clientPhoneMasked = String(appt?.clientPhone || '').trim();
      const status = String(appt?.status || 'Scheduled').trim();
      const appointmentAt = parseIsoDate(`${appt?.date || ''}T${appt?.time || ''}`) || nowIso;
      await client.query(
        `
        INSERT INTO normalized_appointments
          (scope, appointment_id, lead_id, user_key, team, client_name, client_phone_masked, appointment_at, status, created_at, updated_at)
        VALUES
          ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), NOW())
        `,
        [scope, appointmentId, leadId, userKey, team, clientName, clientPhoneMasked, appointmentAt, status]
      );
    }

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function sendResetEmail(toEmail, token, scope) {
  if (!isResetEmailConfigured()) return false;
  const normalizedPath = APP_RESET_PATH.startsWith('/') ? APP_RESET_PATH : `/${APP_RESET_PATH}`;
  const resetUrl = `${APP_PUBLIC_URL.replace(/\/$/, '')}${normalizedPath}#reset?token=${encodeURIComponent(
    token
  )}&scope=${encodeURIComponent(scope)}`;
  const brandColor = '#f26a21';
  const bgColor = '#0f1419';
  const cardColor = '#1b2229';
  const textColor = '#f6f2ee';
  const muted = '#c9c1bb';
  const logoPath = resolveEmailLogoPath();
  const hasLogo = Boolean(logoPath);
  const info = await mailer.sendMail({
    from: SMTP_FROM,
    replyTo: SMTP_REPLY_TO || undefined,
    to: toEmail,
    subject: 'Matla JFA Password Reset',
    text: `Use this link to reset your password: ${resetUrl}\n\nIf you did not request this, you can ignore this email.`,
    html: `
      <div style="margin:0;padding:32px;background:${bgColor};font-family:Arial,Helvetica,sans-serif;color:${textColor};">
        <div style="max-width:560px;margin:0 auto;background:${cardColor};border-radius:18px;padding:28px;border:1px solid rgba(255,255,255,0.08);">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
            ${hasLogo
              ? `<img src="cid:matla-logo" alt="Matla Life" style="width:44px;height:44px;border-radius:12px;object-fit:contain;background:${brandColor};padding:4px;">`
              : `<div style="width:44px;height:44px;border-radius:12px;background:${brandColor};display:flex;align-items:center;justify-content:center;color:white;font-weight:700;">M</div>`}
            <div>
              <h2 style="margin:0;font-size:20px;">Matla JFA Security</h2>
              <p style="margin:4px 0 0;color:${muted};font-size:13px;">Password reset request</p>
            </div>
          </div>
          <p style="font-size:15px;line-height:1.5;color:${textColor};">We received a request to reset your password. Click the button below to create a new one.</p>
          <div style="margin:22px 0;">
            <a href="${resetUrl}" style="display:inline-block;background:${brandColor};color:#fff;text-decoration:none;padding:12px 18px;border-radius:10px;font-weight:700;">Reset Password</a>
          </div>
          <p style="font-size:13px;color:${muted};line-height:1.5;">If the button doesn't work, copy and paste this link into your browser:</p>
          <p style="word-break:break-all;font-size:12px;color:${muted};">${resetUrl}</p>
          <hr style="border:none;border-top:1px solid rgba(255,255,255,0.08);margin:20px 0;">
          <p style="font-size:12px;color:${muted};margin:0;">If you didn't request this, you can safely ignore this email.</p>
        </div>
      </div>
    `,
    attachments: hasLogo
      ? [
          {
            filename: 'matla-life-logo2.png',
            path: logoPath,
            cid: 'matla-logo'
          }
        ]
      : undefined
  });
  return Boolean(info?.messageId);
}

function resolveEmailLogoPath() {
  const candidates = [
    path.join(STATIC_DIR, 'matla-life-logo2.png'),
    path.join(backendRoot, 'matla-life-logo2.png'),
    path.join(process.cwd(), 'matla-life-logo2.png'),
    path.join(process.cwd(), 'static', 'matla-life-logo2.png')
  ];
  for (const candidate of candidates) {
    try {
      if (candidate && fs.existsSync(candidate)) return candidate;
    } catch (_) {
      // ignore
    }
  }
  return '';
}

async function sendPasswordChangedEmail(toEmail) {
  if (!isResetEmailConfigured()) return false;
  const brandColor = '#f26a21';
  const bgColor = '#0f1419';
  const cardColor = '#1b2229';
  const textColor = '#f6f2ee';
  const muted = '#c9c1bb';
  const logoPath = resolveEmailLogoPath();
  const hasLogo = Boolean(logoPath);
  const info = await mailer.sendMail({
    from: SMTP_FROM,
    replyTo: SMTP_REPLY_TO || undefined,
    to: toEmail,
    subject: 'Matla JFA Password Changed',
    text: 'Your Matla JFA password was successfully changed. If this was not you, contact admin immediately.',
    html: `
      <div style="margin:0;padding:32px;background:${bgColor};font-family:Arial,Helvetica,sans-serif;color:${textColor};">
        <div style="max-width:560px;margin:0 auto;background:${cardColor};border-radius:18px;padding:28px;border:1px solid rgba(255,255,255,0.08);">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:18px;">
            ${hasLogo
              ? `<img src="cid:matla-logo" alt="Matla Life" style="width:44px;height:44px;border-radius:12px;object-fit:contain;background:${brandColor};padding:4px;">`
              : `<div style="width:44px;height:44px;border-radius:12px;background:${brandColor};display:flex;align-items:center;justify-content:center;color:white;font-weight:700;">M</div>`}
            <div>
              <h2 style="margin:0;font-size:20px;">Matla JFA Security</h2>
              <p style="margin:4px 0 0;color:${muted};font-size:13px;">Password changed</p>
            </div>
          </div>
          <p style="font-size:15px;line-height:1.5;color:${textColor};">Your password was changed successfully.</p>
          <p style="font-size:13px;color:${muted};line-height:1.5;">If you did not perform this action, contact Admin immediately.</p>
        </div>
      </div>
    `,
    attachments: hasLogo
      ? [
          {
            filename: 'matla-life-logo2.png',
            path: logoPath,
            cid: 'matla-logo'
          }
        ]
      : undefined
  });
  return Boolean(info?.messageId);
}

function hashRefreshToken(token) {
  return crypto.createHash('sha256').update(String(token || ''), 'utf8').digest('hex');
}

function createSessionIdentifiers(providedSessionId = '') {
  const sessionId = sanitizeActor(providedSessionId) || `sess-${crypto.randomUUID()}`;
  const refreshToken = crypto.randomBytes(40).toString('hex');
  const refreshTokenHash = hashRefreshToken(refreshToken);
  return { sessionId, refreshToken, refreshTokenHash };
}

async function upsertAuthSession({
  scope,
  sessionId,
  userKey,
  username,
  role,
  team,
  ipAddress,
  userAgent,
  refreshTokenHash,
  mfa
}) {
  await pool.query(
    `
    INSERT INTO auth_sessions
      (scope, session_id, user_key, username, role, team, ip_address, user_agent, refresh_token_hash, mfa, created_at, last_seen_at, expires_at)
    VALUES
      ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW(), NOW(), NOW() + ($11::text || ' seconds')::interval)
    ON CONFLICT (scope, session_id)
    DO UPDATE SET
      user_key = EXCLUDED.user_key,
      username = EXCLUDED.username,
      role = EXCLUDED.role,
      team = EXCLUDED.team,
      ip_address = EXCLUDED.ip_address,
      user_agent = EXCLUDED.user_agent,
      refresh_token_hash = EXCLUDED.refresh_token_hash,
      mfa = EXCLUDED.mfa,
      last_seen_at = NOW(),
      expires_at = NOW() + ($11::text || ' seconds')::interval,
      revoked_at = NULL,
      revoke_reason = ''
    `,
    [scope, sessionId, userKey, username, role, team, ipAddress, userAgent, refreshTokenHash, Boolean(mfa), String(SESSION_REFRESH_TTL_SECONDS)]
  );
}

async function loadActiveSession(scope, sessionId) {
  const result = await pool.query(
    `
    SELECT *
    FROM auth_sessions
    WHERE scope = $1
      AND session_id = $2
      AND revoked_at IS NULL
      AND expires_at >= NOW()
    LIMIT 1
    `,
    [scope, sessionId]
  );
  if (!result.rows.length) return null;
  const row = result.rows[0];
  if (row.last_seen_at) {
    const idleSeconds = Math.floor((Date.now() - new Date(row.last_seen_at).getTime()) / 1000);
    if (idleSeconds > SESSION_IDLE_TIMEOUT_SECONDS) return null;
  }
  return row;
}

async function revokeSession(scope, sessionId, reason = 'manual') {
  await pool.query(
    `
    UPDATE auth_sessions
    SET revoked_at = NOW(),
        revoke_reason = $3
    WHERE scope = $1
      AND session_id = $2
      AND revoked_at IS NULL
    `,
    [scope, sessionId, String(reason || 'manual').slice(0, 120)]
  );
}

async function queueEmail(template, scope, toEmail, payload = {}) {
  const result = await pool.query(
    `
    INSERT INTO smtp_outbox
      (scope, template, to_email, payload_json, status, attempts, next_attempt_at, created_at)
    VALUES
      ($1, $2, $3, $4, 'pending', 0, NOW(), NOW())
    RETURNING id
    `,
    [scope, template, toEmail, JSON.stringify(payload || {})]
  );
  return safeInt(result.rows?.[0]?.id, 0);
}

async function sendResetEmailNow(toEmail, token, scope) {
  return sendResetEmail(toEmail, token, scope);
}

async function sendPasswordChangedEmailNow(toEmail) {
  return sendPasswordChangedEmail(toEmail);
}

async function dispatchSmtpOutboxOnce() {
  if (!isResetEmailConfigured()) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const pending = await client.query(
      `
      SELECT id, scope, template, to_email, payload_json, attempts
      FROM smtp_outbox
      WHERE status IN ('pending', 'retry')
        AND next_attempt_at <= NOW()
      ORDER BY id ASC
      LIMIT $1
      FOR UPDATE SKIP LOCKED
      `,
      [SMTP_QUEUE_BATCH_SIZE]
    );
    for (const row of pending.rows) {
      const payload = parseJsonSafely(row.payload_json, {}) || {};
      let sent = false;
      let errorMessage = '';
      try {
        if (row.template === 'reset') {
          sent = await sendResetEmailNow(row.to_email, String(payload.token || ''), row.scope);
        } else if (row.template === 'password-changed') {
          sent = await sendPasswordChangedEmailNow(row.to_email);
        } else {
          throw new Error(`Unknown email template: ${row.template}`);
        }
      } catch (error) {
        errorMessage = String(error?.message || error || 'Dispatch failed').slice(0, 500);
      }

      if (sent) {
        await client.query(
          `
          UPDATE smtp_outbox
          SET status = 'sent',
              sent_at = NOW(),
              last_error = ''
          WHERE id = $1
          `,
          [row.id]
        );
        continue;
      }

      const nextAttempts = safeInt(row.attempts, 0) + 1;
      const isDead = nextAttempts >= SMTP_QUEUE_RETRY_LIMIT;
      const backoffMinutes = Math.min(60, 2 ** Math.min(nextAttempts, 6));
      await client.query(
        `
        UPDATE smtp_outbox
        SET attempts = $2,
            status = $3,
            last_error = $4,
            next_attempt_at = CASE WHEN $3 = 'dead' THEN next_attempt_at ELSE NOW() + ($5::text || ' minutes')::interval END
        WHERE id = $1
        `,
        [row.id, nextAttempts, isDead ? 'dead' : 'retry', errorMessage || 'Dispatch failed', String(backoffMinutes)]
      );
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
  } finally {
    client.release();
  }
}

const app = express();
app.disable('x-powered-by');
app.use(helmet());
app.use(express.json({ limit: '12mb' }));
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
  })
);
const authRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many authentication requests. Try again in 15 minutes.' }
});
const resetRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many password reset attempts. Try again in 15 minutes.' }
});
app.use(
  cors({
    origin: ALLOWED_ORIGIN === '*' ? true : ALLOWED_ORIGIN
  })
);
app.use('/api', authMiddleware, endpointAccessPolicyMiddleware);

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    service: 'matla-jfa-secure-api',
    resetEmailConfigured: isResetEmailConfigured()
  });
});

app.get('/api/auth/config', authMiddleware, (_req, res) => {
  res.json({
    ok: true,
    resetEmailConfigured: isResetEmailConfigured(),
    appPublicUrlConfigured: Boolean(APP_PUBLIC_URL),
    smtpConfigured: Boolean(SMTP_HOST && SMTP_FROM),
    signedSessionEnabled: true,
    require2faForPrivileged: REQUIRE_2FA_FOR_PRIVILEGED
  });
});

app.post('/api/auth/register', authMiddleware, authRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const usernameInput = String(req.body?.username || '').trim();
    const emailInput = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '').trim();
    const teamInput = String(req.body?.team || '').trim();
    const sessionId = sanitizeActor(req.body?.sessionId || req.get('x-app-session'));
    const termsAcceptedAt = parseIsoDate(req.body?.termsAcceptedAt) || new Date().toISOString();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);

    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    if (!usernameInput) return res.status(400).json({ error: 'Username is required' });
    if (!emailInput || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput)) {
      return res.status(400).json({ error: 'Valid email is required' });
    }
    const passwordCheck = validateStrongPassword(password);
    if (!passwordCheck.ok) return res.status(400).json({ error: passwordCheck.message });

    const key = normalizeKey(usernameInput);
    if (!key || key === 'admin') {
      return res.status(400).json({ error: 'Username is reserved' });
    }

    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    if (accounts[key]) return res.status(409).json({ error: 'Username already exists' });

    const emailTaken = Object.values(accounts || {}).some((entry) => {
      const entryEmail = String(entry?.email || '').trim().toLowerCase();
      return Boolean(entryEmail && entryEmail === emailInput);
    });
    if (emailTaken) return res.status(409).json({ error: 'Email already exists' });

    const record = createPasswordRecord(password);
    const nowIso = new Date().toISOString();
    const account = {
      username: usernameInput,
      email: emailInput,
      team: teamInput,
      adminOnly: false,
      active: true,
      permissions: { admin: false, learning: true, forms: true, leads: true, settings: true },
      createdAt: nowIso,
      createdBy: 'self-signup',
      termsAcceptedAt,
      termsVersion: '2026-02-13',
      lastLoginAt: nowIso,
      updatedAt: nowIso,
      passwordSalt: record.salt,
      passwordHash: record.bcryptHash,
      passwordHashLegacy: record.hash
    };
    accounts[key] = account;
    writePayloadJson(payload, 'jfaUserAccounts', accounts);
    await saveAppState(scope, payload);

    const role = 'PERSONAL';
    const { sessionId: finalSessionId, refreshToken, refreshTokenHash } = createSessionIdentifiers(sessionId);
    const now = Math.floor(Date.now() / 1000);
    const exp = now + SESSION_TOKEN_TTL_SECONDS;
    const claims = {
      sub: key,
      scope,
      role,
      username: String(account.username || key),
      actor: String(account.username || key),
      team: String(account.team || ''),
      userKey: key,
      sessionId: finalSessionId,
      iat: now,
      exp,
      mfa: false
    };
    const accessToken = signSessionToken(claims);
    await upsertAuthSession({
      scope,
      sessionId: finalSessionId,
      userKey: key,
      username: String(account.username || key),
      role,
      team: String(account.team || ''),
      ipAddress,
      userAgent,
      refreshTokenHash,
      mfa: false
    });

    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || String(account.username || key),
      actorRole: role,
      sessionId: finalSessionId,
      action: 'AUTH_REGISTER',
      details: `account=${key}`,
      source: 'api',
      ipAddress,
      userAgent
    });

    return res.json({
      ok: true,
      registered: true,
      tokenType: 'Bearer',
      accessToken,
      refreshToken,
      expiresIn: SESSION_TOKEN_TTL_SECONDS,
      refreshExpiresIn: SESSION_REFRESH_TTL_SECONDS,
      sessionId: finalSessionId,
      role,
      account: {
        key,
        username: String(account.username || key),
        email: String(account.email || ''),
        team: String(account.team || ''),
        adminOnly: false
      }
    });
  } catch (_error) {
    return res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', authMiddleware, authRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const identifier = String(req.body?.identifier || '').trim();
    const password = String(req.body?.password || '').trim();
    const otpCode = String(req.body?.otp || '').trim();
    const sessionId = sanitizeActor(req.body?.sessionId || req.get('x-app-session'));
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);

    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    if (!identifier || !password) return res.status(400).json({ error: 'Identifier and password are required' });
    const identityKey = normalizeKey(identifier);
    const lockState = await getLoginLockState(scope, identityKey, ipAddress);
    if (lockState.isLocked) {
      return res.status(423).json({
        error: 'Account temporarily locked due to failed login attempts.',
        lockedUntil: lockState.lockedUntil?.toISOString() || null
      });
    }

    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    const match = resolveAccountFromPayload(accounts, identifier);
    if (!match) {
      await registerLoginFailure(scope, identityKey, ipAddress);
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const { key, account } = match;

    if (account?.active === false) return res.status(403).json({ error: 'Account is disabled' });
    if (!verifyAccountPassword(account, password)) {
      await registerLoginFailure(scope, identityKey, ipAddress);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (account.passwordHash && account.passwordSalt && !String(account.passwordHash).startsWith('$2')) {
      const migrated = createPasswordRecord(password);
      account.passwordHash = migrated.bcryptHash;
      account.passwordHashLegacy = migrated.hash;
      account.passwordSalt = migrated.salt;
      account.updatedAt = new Date().toISOString();
      accounts[key] = account;
      writePayloadJson(payload, 'jfaUserAccounts', accounts);
      await saveAppState(scope, payload);
    }

    const role = determineAccountRole(account, key);
    const isPrivileged = role === 'ADMIN' || role === 'TEAM';
    const mfaEnabled = Boolean(account?.twoFactorEnabled && account?.twoFactorSecret);
    if (REQUIRE_2FA_FOR_PRIVILEGED && isPrivileged) {
      if (!mfaEnabled) {
        return res.status(428).json({ error: 'Two-factor setup required for privileged account', code: '2FA_SETUP_REQUIRED' });
      }
      if (!verifyTotpCode(account.twoFactorSecret, otpCode)) {
        return res.status(401).json({ error: 'Invalid two-factor code', code: '2FA_REQUIRED' });
      }
    } else if (mfaEnabled && otpCode) {
      if (!verifyTotpCode(account.twoFactorSecret, otpCode)) {
        return res.status(401).json({ error: 'Invalid two-factor code' });
      }
    } else if (mfaEnabled && !otpCode) {
      return res.status(401).json({ error: 'Two-factor code required', code: '2FA_REQUIRED' });
    }

    const { sessionId: finalSessionId, refreshToken, refreshTokenHash } = createSessionIdentifiers(sessionId);
    const now = Math.floor(Date.now() / 1000);
    const exp = now + SESSION_TOKEN_TTL_SECONDS;
    const claims = {
      sub: key,
      scope,
      role,
      username: String(account.username || key),
      actor: String(account.username || key),
      team: String(account.team || ''),
      userKey: key,
      sessionId: finalSessionId,
      iat: now,
      exp,
      mfa: Boolean(mfaEnabled)
    };
    const accessToken = signSessionToken(claims);
    await upsertAuthSession({
      scope,
      sessionId: finalSessionId,
      userKey: key,
      username: String(account.username || key),
      role,
      team: String(account.team || ''),
      ipAddress,
      userAgent,
      refreshTokenHash,
      mfa: Boolean(mfaEnabled)
    });
    await clearLoginFailures(scope, identityKey, ipAddress);

    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || String(account.username || key),
      actorRole: role,
      sessionId: finalSessionId,
      action: 'AUTH_LOGIN',
      details: `account=${key};mfa=${mfaEnabled ? 'yes' : 'no'}`,
      source: 'api',
      ipAddress,
      userAgent
    });

    return res.json({
      ok: true,
      tokenType: 'Bearer',
      accessToken,
      refreshToken,
      expiresIn: SESSION_TOKEN_TTL_SECONDS,
      refreshExpiresIn: SESSION_REFRESH_TTL_SECONDS,
      sessionId: finalSessionId,
      role,
      account: {
        key,
        username: String(account.username || key),
        email: String(account.email || ''),
        team: String(account.team || ''),
        adminOnly: account.adminOnly === true
      },
      mfaEnabled
    });
  } catch (error) {
    return res.status(500).json({ error: 'Login failed' });
  }
});

app.get('/api/auth/session', authMiddleware, async (req, res) => {
  if (!req?.authContext || req.authContext.type !== 'signed') {
    return res.status(401).json({ error: 'No active signed session' });
  }
  const scope = sanitizeScope(req.authContext.scope);
  const sessionId = sanitizeActor(req.authContext.sessionId);
  const session = await loadActiveSession(scope, sessionId);
  if (!session) {
    return res.status(401).json({ error: 'Session expired or revoked' });
  }
  await pool.query(
    `UPDATE auth_sessions SET last_seen_at = NOW() WHERE scope = $1 AND session_id = $2`,
    [scope, sessionId]
  );
  return res.json({
    ok: true,
    role: sanitizeRole(req.authContext.role),
    actor: sanitizeActor(req.authContext.actor || req.authContext.username),
    userKey: req.authContext.userKey || '',
    scope: scope || '',
    team: String(req.authContext.team || ''),
    mfa: req.authContext.mfa === true,
    sessionId
  });
});

app.post('/api/auth/refresh', authMiddleware, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const refreshToken = String(req.body?.refreshToken || '').trim();
    const sessionId = sanitizeActor(req.body?.sessionId || req.get('x-app-session') || req?.authContext?.sessionId);
    if (!isSafeScope(scope) || !refreshToken || !sessionId) {
      return res.status(400).json({ error: 'Invalid refresh request' });
    }
    const session = await loadActiveSession(scope, sessionId);
    if (!session) return res.status(401).json({ error: 'Session expired or revoked' });
    const providedHash = hashRefreshToken(refreshToken);
    const expectedHash = String(session.refresh_token_hash || '');
    const a = Buffer.from(providedHash, 'utf8');
    const b = Buffer.from(expectedHash, 'utf8');
    if (!expectedHash || a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      await revokeSession(scope, sessionId, 'invalid-refresh-token');
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    const now = Math.floor(Date.now() / 1000);
    const newExp = now + SESSION_TOKEN_TTL_SECONDS;
    const nextRefresh = createSessionIdentifiers(sessionId);
    await upsertAuthSession({
      scope,
      sessionId,
      userKey: String(session.user_key || ''),
      username: String(session.username || session.user_key || ''),
      role: sanitizeRole(session.role),
      team: String(session.team || ''),
      ipAddress: String(session.ip_address || ''),
      userAgent: String(session.user_agent || ''),
      refreshTokenHash: nextRefresh.refreshTokenHash,
      mfa: Boolean(session.mfa)
    });
    const accessToken = signSessionToken({
      sub: String(session.user_key || ''),
      scope,
      role: sanitizeRole(session.role),
      username: String(session.username || session.user_key || ''),
      actor: String(session.username || session.user_key || ''),
      team: String(session.team || ''),
      userKey: String(session.user_key || ''),
      sessionId,
      iat: now,
      exp: newExp,
      mfa: Boolean(session.mfa)
    });
    return res.json({
      ok: true,
      tokenType: 'Bearer',
      accessToken,
      refreshToken: nextRefresh.refreshToken,
      expiresIn: SESSION_TOKEN_TTL_SECONDS,
      refreshExpiresIn: SESSION_REFRESH_TTL_SECONDS,
      sessionId
    });
  } catch (_) {
    return res.status(500).json({ error: 'Refresh failed' });
  }
});

app.post('/api/auth/logout', authMiddleware, async (req, res) => {
  try {
    if (!isSignedSession(req)) {
      return res.status(200).json({ ok: true });
    }
    const scope = sanitizeScope(req.authContext.scope);
    const sessionId = sanitizeActor(req.authContext.sessionId);
    if (scope && sessionId) {
      await revokeSession(scope, sessionId, 'logout');
    }
    return res.json({ ok: true });
  } catch (_) {
    return res.status(500).json({ error: 'Logout failed' });
  }
});

app.get('/api/auth/sessions', authMiddleware, async (req, res) => {
  try {
    if (!isSignedSession(req)) return res.status(401).json({ error: 'Signed session required' });
    const scope = sanitizeScope(req.query.scope || req.authContext.scope);
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    const role = sanitizeRole(req.authContext.role);
    const userKey = normalizeKey(req.authContext.userKey || '');
    const where = role === 'ADMIN'
      ? 'scope = $1'
      : 'scope = $1 AND user_key = $2';
    const params = role === 'ADMIN' ? [scope] : [scope, userKey];
    const result = await pool.query(
      `
      SELECT session_id, user_key, username, role, team, ip_address, user_agent, created_at, last_seen_at, expires_at, revoked_at, revoke_reason
      FROM auth_sessions
      WHERE ${where}
      ORDER BY created_at DESC
      LIMIT 200
      `,
      params
    );
    return res.json({ ok: true, items: result.rows || [] });
  } catch (_) {
    return res.status(500).json({ error: 'Failed to list sessions' });
  }
});

app.delete('/api/auth/sessions/:sessionId', authMiddleware, async (req, res) => {
  try {
    if (!isSignedSession(req)) return res.status(401).json({ error: 'Signed session required' });
    const scope = sanitizeScope(req.body?.scope || req.query?.scope || req.authContext.scope);
    const targetSessionId = sanitizeActor(req.params?.sessionId);
    if (!isSafeScope(scope) || !targetSessionId) return res.status(400).json({ error: 'Invalid request' });
    const role = sanitizeRole(req.authContext.role);
    const currentSessionId = sanitizeActor(req.authContext.sessionId);
    if (role !== 'ADMIN' && targetSessionId !== currentSessionId) {
      return res.status(403).json({ error: 'Admin role required to revoke other sessions' });
    }
    await revokeSession(scope, targetSessionId, `revoked-by-${sanitizeActor(req.authContext.actor || req.authContext.username)}`);
    return res.json({ ok: true });
  } catch (_) {
    return res.status(500).json({ error: 'Failed to revoke session' });
  }
});

app.post('/api/auth/2fa/setup', authMiddleware, authRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const requestedUsername = String(req.body?.username || '').trim();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });

    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    const actorKey = req?.authContext?.userKey || normalizeKey(actorCtx.actor);
    const targetKey = normalizeKey(requestedUsername || actorKey);
    if (!targetKey || !accounts[targetKey]) {
      return res.status(404).json({ error: 'Account not found' });
    }
    if (targetKey !== actorKey && !hasAnyRole(req, ['ADMIN'])) {
      return res.status(403).json({ error: 'Admin role required to manage other accounts' });
    }

    const account = accounts[targetKey] || {};
    const secret = generateTotpSecret();
    account.twoFactorSecret = secret;
    account.twoFactorEnabled = false;
    account.twoFactorUpdatedAt = new Date().toISOString();
    accounts[targetKey] = account;
    writePayloadJson(payload, 'jfaUserAccounts', accounts);
    await saveAppState(scope, payload);

    const issuer = encodeURIComponent('Matla Life Daily Ops');
    const label = encodeURIComponent(`${scope}:${account.username || targetKey}`);
    const otpAuthUrl = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;

    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || targetKey,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: '2FA_SETUP_INIT',
      details: `account=${targetKey}`,
      source: 'api',
      ipAddress,
      userAgent
    });

    return res.json({
      ok: true,
      username: String(account.username || targetKey),
      accountKey: targetKey,
      secret,
      otpAuthUrl,
      hint: 'Scan this in an authenticator app, then verify to enable 2FA.'
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to start 2FA setup' });
  }
});

app.post('/api/auth/2fa/verify-enable', authMiddleware, authRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const requestedUsername = String(req.body?.username || '').trim();
    const code = String(req.body?.code || '').trim();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Invalid 2FA code format' });

    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    const actorKey = req?.authContext?.userKey || normalizeKey(actorCtx.actor);
    const targetKey = normalizeKey(requestedUsername || actorKey);
    if (!targetKey || !accounts[targetKey]) {
      return res.status(404).json({ error: 'Account not found' });
    }
    if (targetKey !== actorKey && !hasAnyRole(req, ['ADMIN'])) {
      return res.status(403).json({ error: 'Admin role required to manage other accounts' });
    }
    const account = accounts[targetKey] || {};
    const secret = String(account.twoFactorSecret || '').trim();
    if (!secret) return res.status(400).json({ error: '2FA setup not initialized' });
    if (!verifyTotpCode(secret, code)) return res.status(401).json({ error: 'Invalid 2FA code' });

    account.twoFactorEnabled = true;
    account.twoFactorEnabledAt = new Date().toISOString();
    accounts[targetKey] = account;
    writePayloadJson(payload, 'jfaUserAccounts', accounts);
    await saveAppState(scope, payload);

    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || targetKey,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: '2FA_ENABLED',
      details: `account=${targetKey}`,
      source: 'api',
      ipAddress,
      userAgent
    });

    return res.json({ ok: true, enabled: true, accountKey: targetKey });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to enable 2FA' });
  }
});

app.post('/api/auth/2fa/disable', authMiddleware, authRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const requestedUsername = String(req.body?.username || '').trim();
    const code = String(req.body?.code || '').trim();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });

    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    const actorKey = req?.authContext?.userKey || normalizeKey(actorCtx.actor);
    const targetKey = normalizeKey(requestedUsername || actorKey);
    if (!targetKey || !accounts[targetKey]) {
      return res.status(404).json({ error: 'Account not found' });
    }
    const isAdminAction = targetKey !== actorKey;
    if (isAdminAction && !hasAnyRole(req, ['ADMIN'])) {
      return res.status(403).json({ error: 'Admin role required to manage other accounts' });
    }

    const account = accounts[targetKey] || {};
    const secret = String(account.twoFactorSecret || '').trim();
    if (secret && !isAdminAction) {
      if (!verifyTotpCode(secret, code)) {
        return res.status(401).json({ error: 'Valid 2FA code required to disable 2FA' });
      }
    }

    delete account.twoFactorSecret;
    account.twoFactorEnabled = false;
    account.twoFactorDisabledAt = new Date().toISOString();
    accounts[targetKey] = account;
    writePayloadJson(payload, 'jfaUserAccounts', accounts);
    await saveAppState(scope, payload);

    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || targetKey,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: '2FA_DISABLED',
      details: `account=${targetKey}`,
      source: 'api',
      ipAddress,
      userAgent
    });

    return res.json({ ok: true, enabled: false, accountKey: targetKey });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

app.get('/api/state/load', authMiddleware, async (req, res) => {
  try {
    const scope = sanitizeScope(req.query.scope);
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    const result = await pool.query(
      `SELECT scope, payload_enc_b64, iv_b64, tag_b64, updated_at FROM app_state WHERE scope = $1`,
      [scope]
    );
    if (!result.rows.length) {
      return res.json({ scope, payload: {}, updatedAt: null });
    }
    const row = result.rows[0];
    const payload = decryptPayload(row);
    return res.json({
      scope,
      payload,
      updatedAt: row.updated_at
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load state' });
  }
});

app.post('/api/state/save', authMiddleware, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const payload = req.body?.payload;
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    const payloadValidation = validateStatePayloadShape(payload);
    if (!payloadValidation.ok) {
      return res.status(400).json({ error: payloadValidation.message || 'Invalid payload' });
    }
    const payloadBytes = estimatePayloadBytes(payload);
    if (!Number.isFinite(payloadBytes) || payloadBytes > MAX_PAYLOAD_BYTES) {
      return res.status(413).json({ error: `Payload too large (max ${MAX_PAYLOAD_BYTES} bytes)` });
    }
    const encrypted = encryptPayload(payload);
    const result = await pool.query(
      `
      INSERT INTO app_state (scope, payload_enc_b64, iv_b64, tag_b64, updated_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (scope)
      DO UPDATE SET
        payload_enc_b64 = EXCLUDED.payload_enc_b64,
        iv_b64 = EXCLUDED.iv_b64,
        tag_b64 = EXCLUDED.tag_b64,
        updated_at = NOW()
      RETURNING updated_at
      `,
      [scope, encrypted.payloadEnc, encrypted.iv, encrypted.tag]
    );
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'STATE_SAVE',
      details: `keys=${Object.keys(payload || {}).length}`,
      source: 'api',
      ipAddress,
      userAgent
    });
    return res.json({
      ok: true,
      scope,
      updatedAt: result.rows[0].updated_at
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save state' });
  }
});

app.get('/api/state/backup', authMiddleware, async (req, res) => {
  try {
    if (!hasAdminRole(req)) {
      return res.status(403).json({ error: 'Admin role required for backup export' });
    }
    const scope = sanitizeScope(req.query.scope);
    const exportReason = String(req.query.reason || '').trim();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    if (exportReason.length < 5) {
      return res.status(400).json({ error: 'Export reason (min 5 chars) is required' });
    }
    const result = await pool.query(
      `SELECT scope, payload_enc_b64, iv_b64, tag_b64, updated_at FROM app_state WHERE scope = $1`,
      [scope]
    );
    if (!result.rows.length) {
      return res.status(404).json({ error: 'No backup found for scope' });
    }
    const row = result.rows[0];
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'BACKUP_EXPORT',
      details: `updatedAt=${row.updated_at};reason=${exportReason.slice(0, 120)}`,
      source: 'api',
      ipAddress,
      userAgent
    });
    return res.json({
      ok: true,
      scope,
      backup: {
        version: 1,
        payloadEncB64: row.payload_enc_b64,
        ivB64: row.iv_b64,
        tagB64: row.tag_b64,
        updatedAt: row.updated_at
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to create backup' });
  }
});

app.post('/api/state/restore', authMiddleware, async (req, res) => {
  try {
    if (!hasAdminRole(req)) {
      return res.status(403).json({ error: 'Admin role required for restore' });
    }
    const scope = sanitizeScope(req.body?.scope);
    const backup = req.body?.backup;
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    const confirmPhrase = String(req.body?.confirmPhrase || '').trim();
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    if (confirmPhrase !== 'RESTORE') {
      return res.status(400).json({ error: 'confirmPhrase must be RESTORE' });
    }
    if (!isEncryptedBackupShape(backup)) {
      return res.status(400).json({ error: 'Invalid backup shape' });
    }
    const result = await pool.query(
      `
      INSERT INTO app_state (scope, payload_enc_b64, iv_b64, tag_b64, updated_at)
      VALUES ($1, $2, $3, $4, NOW())
      ON CONFLICT (scope)
      DO UPDATE SET
        payload_enc_b64 = EXCLUDED.payload_enc_b64,
        iv_b64 = EXCLUDED.iv_b64,
        tag_b64 = EXCLUDED.tag_b64,
        updated_at = NOW()
      RETURNING updated_at
      `,
      [scope, backup.payloadEncB64, backup.ivB64, backup.tagB64]
    );
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'BACKUP_RESTORE',
      details: `restoredAt=${result.rows[0]?.updated_at || ''}`,
      source: 'api',
      ipAddress,
      userAgent
    });
    return res.json({
      ok: true,
      scope,
      restoredAt: result.rows[0]?.updated_at || new Date().toISOString()
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to restore backup' });
  }
});

app.post('/api/auth/request-reset', authMiddleware, authRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const email = (req.body?.email || '').toString().trim().toLowerCase();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    if (!isResetEmailConfigured()) {
      return res.status(503).json({
        error: 'Password reset email is not configured on the server.'
      });
    }
    if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
      return res.status(200).json({ ok: true });
    }
    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    const profiles = parsePayloadJson(payload, 'jfaProfiles', {});
    let accountKey = '';
    Object.entries(accounts).some(([key, account]) => {
      if (String(account?.email || '').toLowerCase() === email) {
        accountKey = key;
        return true;
      }
      return false;
    });
    if (!accountKey) {
      Object.entries(profiles).some(([key, profile]) => {
        if (String(profile?.email || '').toLowerCase() === email) {
          accountKey = key;
          return true;
        }
        return false;
      });
    }
    if (!accountKey) {
      return res.json({ ok: true });
    }
    const token = crypto.randomBytes(24).toString('hex');
    const tokenHash = hashToken(token);
    const expiresAt = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query(
      `
      DELETE FROM password_reset_tokens
      WHERE scope = $1
        AND account_key = $2
      `,
      [scope, accountKey]
    );
    await pool.query(
      `
      INSERT INTO password_reset_tokens (scope, account_key, email, token_hash, expires_at)
      VALUES ($1, $2, $3, $4, $5)
      `,
      [scope, accountKey, email, tokenHash, expiresAt.toISOString()]
    );
    const outboxId = await queueEmail('reset', scope, email, { token, scope });
    // Try immediate dispatch so caller gets real success/failure feedback.
    await dispatchSmtpOutboxOnce();
    if (outboxId > 0) {
      const outboxResult = await pool.query(
        `
        SELECT status, COALESCE(last_error, '') AS last_error
        FROM smtp_outbox
        WHERE id = $1
        LIMIT 1
        `,
        [outboxId]
      );
      const outboxRow = outboxResult.rows?.[0] || null;
      if (!outboxRow || outboxRow.status !== 'sent') {
        const reason = String(outboxRow?.last_error || '').trim();
        return res.status(500).json({
          error: reason ? `Failed to send reset email: ${reason}` : 'Failed to send reset email'
        });
      }
    }
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || email,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'PASSWORD_RESET_REQUEST',
      details: `email=${email};queued=true`,
      source: 'api',
      ipAddress,
      userAgent
    });
    return res.json({ ok: true, queued: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to request reset email' });
  }
});

app.post('/api/auth/reset', authMiddleware, resetRateLimiter, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    const token = (req.body?.token || '').toString().trim();
    const newPassword = (req.body?.newPassword || '').toString().trim();
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);
    if (!isSafeScope(scope) || !token) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    const passwordValidation = validateStrongPassword(newPassword);
    if (!passwordValidation.ok) {
      return res.status(400).json({ error: passwordValidation.message });
    }
    const tokenHash = hashToken(token);
    const tokenRes = await pool.query(
      `
      SELECT id, account_key, email, expires_at, used_at
      FROM password_reset_tokens
      WHERE scope = $1 AND token_hash = $2
      LIMIT 1
      `,
      [scope, tokenHash]
    );
    if (!tokenRes.rows.length) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    const tokenRow = tokenRes.rows[0];
    if (tokenRow.used_at || new Date(tokenRow.expires_at) < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }
    const { payload } = await loadAppState(scope);
    const accounts = parsePayloadJson(payload, 'jfaUserAccounts', {});
    const account = accounts[tokenRow.account_key];
    if (!account) {
      return res.status(400).json({ error: 'Account not found' });
    }
    const record = createPasswordRecord(newPassword);
    account.passwordHash = record.bcryptHash;
    account.passwordSalt = record.salt;
    account.passwordHashLegacy = record.hash;
    delete account.password;
    account.updatedAt = new Date().toISOString();
    account.updatedBy = 'password-reset';
    accounts[tokenRow.account_key] = account;
    writePayloadJson(payload, 'jfaUserAccounts', accounts);
    const audit = parsePayloadJson(payload, 'userMgmtAudit', []);
    audit.unshift({
      timestamp: new Date().toISOString(),
      action: 'Password reset (email)',
      detail: `Account: ${account.username || tokenRow.account_key}`,
      by: 'system'
    });
    writePayloadJson(payload, 'userMgmtAudit', audit.slice(0, 200));
    await saveAppState(scope, payload);
    await pool.query(
      `UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`,
      [tokenRow.id]
    );
    await pool.query(
      `
      DELETE FROM password_reset_tokens
      WHERE scope = $1
        AND account_key = $2
        AND (used_at IS NOT NULL OR expires_at < NOW())
      `,
      [scope, tokenRow.account_key]
    );
    if (String(tokenRow.email || '').trim()) {
      await queueEmail('password-changed', scope, String(tokenRow.email || '').trim(), { scope });
    }
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor || tokenRow.account_key,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'PASSWORD_RESET_COMPLETE',
      details: `account=${tokenRow.account_key}`,
      source: 'api',
      ipAddress,
      userAgent
    });
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to reset password' });
  }
});

app.post('/api/admin/access-log', authMiddleware, async (req, res) => {
  try {
    const actorCtx = getActorContext(req);
    if (!hasAnyRole(req, ['ADMIN', 'TEAM'])) {
      return res.status(403).json({ error: 'Admin or Team role required' });
    }
    const scope = sanitizeScope(req.body?.scope);
    const username = (req.body?.username || '').toString().trim();
    const section = (req.body?.section || 'Admin (All)').toString().trim();
    const role = (req.body?.role || 'PERSONAL').toString().trim();
    const source = (req.body?.source || 'web').toString().trim();
    const userAgent = (req.body?.userAgent || '').toString().slice(0, 800);
    const happenedAtRaw = (req.body?.happenedAt || '').toString().trim();
    const happenedAt = happenedAtRaw ? new Date(happenedAtRaw) : new Date();
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    if (!isSafeUsername(username)) {
      return res.status(400).json({ error: 'Invalid username' });
    }
    if (!section || section.length > 120) {
      return res.status(400).json({ error: 'Invalid section' });
    }
    if (!role || role.length > 40 || !source || source.length > 40) {
      return res.status(400).json({ error: 'Invalid role/source' });
    }
    if (Number.isNaN(happenedAt.getTime())) {
      return res.status(400).json({ error: 'Invalid happenedAt' });
    }
    const { ipAddress, userAgent: requestUa } = getRequestMeta(req);
    await pool.query(
      `
      INSERT INTO admin_access_log
        (scope, username, section, role, source, user_agent, ip_address, happened_at)
      VALUES
        ($1, $2, $3, $4, $5, $6, $7, $8)
      `,
      [scope, username, section, role, source, userAgent, ipAddress, happenedAt.toISOString()]
    );
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'ADMIN_ACCESS_LOG',
      details: `${username} -> ${section}/${role}`,
      source,
      ipAddress,
      userAgent: requestUa || userAgent
    });
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to save access log' });
  }
});

app.post('/api/audit/append', authMiddleware, async (req, res) => {
  try {
    const scope = sanitizeScope(req.body?.scope);
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    const actorCtx = getActorContext(req);
    const action = String(req.body?.action || '').trim();
    const details = String(req.body?.details || '').trim();
    if (!action || action.length > 120) {
      return res.status(400).json({ error: 'Invalid action' });
    }
    const { ipAddress, userAgent } = getRequestMeta(req);
    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action,
      details,
      source: String(req.body?.source || 'web').slice(0, 40),
      ipAddress,
      userAgent
    });
    return res.json({ ok: true });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to append audit event' });
  }
});

app.get('/api/audit/integrity', authMiddleware, async (req, res) => {
  try {
    if (!hasAdminRole(req)) {
      return res.status(403).json({ error: 'Admin role required' });
    }
    const scope = sanitizeScope(req.query.scope);
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    const rows = await pool.query(
      `
      SELECT id, scope, actor, actor_role, session_id, action, details, source, ip_address, user_agent, prev_hash, entry_hash
      FROM immutable_audit_log
      WHERE scope = $1
      ORDER BY id ASC
      LIMIT 5000
      `,
      [scope]
    );
    let previous = '';
    let invalidAt = null;
    for (const entry of rows.rows) {
      const expected = crypto.createHash('sha256').update(
        `${entry.scope}|${entry.actor}|${entry.actor_role}|${entry.session_id}|${entry.action}|${entry.details}|${entry.source}|${entry.ip_address}|${entry.user_agent}|${previous}`,
        'utf8'
      ).digest('hex');
      if ((entry.prev_hash || '') !== previous || (entry.entry_hash || '') !== expected) {
        invalidAt = Number(entry.id);
        break;
      }
      previous = entry.entry_hash || '';
    }
    return res.json({
      ok: true,
      scope,
      checked: rows.rows.length,
      valid: invalidAt == null,
      invalidAt
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to verify audit integrity' });
  }
});

app.get('/api/state/snapshots', authMiddleware, async (req, res) => {
  try {
    if (!hasAdminRole(req)) {
      return res.status(403).json({ error: 'Admin role required' });
    }
    const scope = sanitizeScope(req.query.scope);
    if (!isSafeScope(scope)) {
      return res.status(400).json({ error: 'Invalid scope' });
    }
    const result = await pool.query(
      `
      SELECT id, scope, source, created_at
      FROM app_state_snapshots
      WHERE scope = $1
      ORDER BY created_at DESC
      LIMIT 200
      `,
      [scope]
    );
    return res.json({ ok: true, items: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to list snapshots' });
  }
});

app.get('/api/metrics', authMiddleware, async (req, res) => {
  try {
    if (!hasAdminRole(req)) {
      return res.status(403).json({ error: 'Admin role required' });
    }
    const [stateRows, auditRows, resetRows, activityRows] = await Promise.all([
      pool.query(`SELECT count(*)::int AS total, max(updated_at) AS last_update FROM app_state`),
      pool.query(`SELECT count(*)::int AS total, max(created_at) AS last_event FROM immutable_audit_log`),
      pool.query(`
        SELECT
          count(*) FILTER (WHERE used_at IS NULL AND expires_at >= NOW())::int AS active_tokens,
          count(*) FILTER (WHERE used_at IS NULL AND expires_at < NOW())::int AS expired_tokens
        FROM password_reset_tokens
      `),
      pool.query(`
        SELECT state, count(*)::int AS sessions
        FROM pg_stat_activity
        WHERE datname = current_database()
        GROUP BY state
      `)
    ]);
    return res.json({
      ok: true,
      metrics: {
        appState: stateRows.rows[0] || { total: 0, last_update: null },
        audit: auditRows.rows[0] || { total: 0, last_event: null },
        resetTokens: resetRows.rows[0] || { active_tokens: 0, expired_tokens: 0 },
        dbSessions: activityRows.rows || []
      }
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load metrics' });
  }
});

app.get('/api/analytics/dashboard', authMiddleware, async (req, res) => {
  try {
    if (!hasAnyRole(req, ['ADMIN', 'TEAM'])) {
      return res.status(403).json({ error: 'Admin or Team role required' });
    }
    const scope = sanitizeScope(req.query.scope);
    const team = String(req.query.team || '').trim();
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    const teamFilter = team ? ' AND jfa_team = $2 ' : '';
    const params = team ? [scope, team] : [scope];

    const [leadTotals, paymentBreakdown, teamLeaderboard, appointmentStats, underperformers] = await Promise.all([
      pool.query(
        `
        SELECT
          count(*)::int AS total_leads,
          count(*) FILTER (WHERE payment_status = 'Pending')::int AS pending,
          count(*) FILTER (WHERE payment_status = 'Successful')::int AS successful,
          count(*) FILTER (WHERE payment_status = 'Unsuccessful')::int AS unsuccessful
        FROM normalized_leads
        WHERE scope = $1 ${teamFilter}
        `,
        params
      ),
      pool.query(
        `
        SELECT payment_status, count(*)::int AS total
        FROM normalized_leads
        WHERE scope = $1 ${teamFilter}
        GROUP BY payment_status
        ORDER BY total DESC
        `,
        params
      ),
      pool.query(
        `
        SELECT jfa_team AS team, count(*)::int AS total
        FROM normalized_leads
        WHERE scope = $1 ${teamFilter}
        GROUP BY jfa_team
        ORDER BY total DESC
        LIMIT 20
        `,
        params
      ),
      pool.query(
        `
        SELECT
          count(*)::int AS total_appointments,
          count(*) FILTER (WHERE appointment_at >= NOW())::int AS upcoming_appointments,
          count(*) FILTER (WHERE appointment_at < NOW() - interval '30 minutes' AND status IN ('Scheduled', 'Pending'))::int AS missed_appointments
        FROM normalized_appointments
        WHERE scope = $1
        ${team ? ' AND team = $2' : ''}
        `,
        team ? [scope, team] : [scope]
      ),
      pool.query(
        `
        SELECT jfa_name, jfa_team AS team, count(*)::int AS monthly_leads
        FROM normalized_leads
        WHERE scope = $1
          AND lead_date >= date_trunc('month', NOW())::date
          ${team ? ' AND jfa_team = $2 ' : ''}
        GROUP BY jfa_name, jfa_team
        HAVING count(*) < 20
        ORDER BY monthly_leads ASC, jfa_name ASC
        `,
        team ? [scope, team] : [scope]
      )
    ]);

    return res.json({
      ok: true,
      scope,
      team: team || null,
      summary: leadTotals.rows[0] || {},
      paymentBreakdown: paymentBreakdown.rows || [],
      teamLeaderboard: teamLeaderboard.rows || [],
      appointments: appointmentStats.rows[0] || {},
      underperformers: underperformers.rows || []
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load analytics dashboard' });
  }
});

app.get('/api/quality/report', authMiddleware, async (req, res) => {
  try {
    if (!hasAnyRole(req, ['ADMIN', 'TEAM'])) {
      return res.status(403).json({ error: 'Admin or Team role required' });
    }
    const scope = sanitizeScope(req.query.scope);
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    const team = String(req.query.team || '').trim();
    const baseParams = team ? [scope, team] : [scope];
    const teamSql = team ? ' AND jfa_team = $2 ' : '';

    const [overview, duplicateClients, unassignedLeads] = await Promise.all([
      pool.query(
        `
        SELECT
          count(*)::int AS total_leads,
          count(*) FILTER (WHERE has_geotag = false)::int AS missing_geotag,
          count(*) FILTER (WHERE has_signature = false)::int AS missing_signature,
          count(*) FILTER (WHERE payment_status = 'Pending' AND fa_assigned_user_key = '')::int AS pending_without_fa
        FROM normalized_leads
        WHERE scope = $1 ${teamSql}
        `,
        baseParams
      ),
      pool.query(
        `
        SELECT client_id_hash, count(*)::int AS duplicate_count
        FROM normalized_leads
        WHERE scope = $1
          ${teamSql}
          AND client_id_hash <> ''
        GROUP BY client_id_hash
        HAVING count(*) > 1
        ORDER BY duplicate_count DESC
        LIMIT 25
        `,
        baseParams
      ),
      pool.query(
        `
        SELECT lead_id, jfa_name, jfa_team, payment_status, lead_date
        FROM normalized_leads
        WHERE scope = $1
          ${teamSql}
          AND payment_status = 'Pending'
          AND fa_assigned_user_key = ''
        ORDER BY lead_date DESC
        LIMIT 200
        `,
        baseParams
      )
    ]);

    return res.json({
      ok: true,
      scope,
      team: team || null,
      summary: overview.rows[0] || {},
      duplicateClients: duplicateClients.rows || [],
      pendingUnassignedLeads: unassignedLeads.rows || []
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to load quality report' });
  }
});

app.get('/api/sensitive/:recordType/:recordKey', authMiddleware, async (req, res) => {
  try {
    if (!hasAdminRole(req)) {
      return res.status(403).json({ error: 'Admin role required' });
    }
    const scope = sanitizeScope(req.query.scope);
    const recordType = String(req.params?.recordType || '').trim().toLowerCase();
    const recordKey = String(req.params?.recordKey || '').trim();
    if (!isSafeScope(scope) || !recordType || !recordKey) {
      return res.status(400).json({ error: 'Invalid request' });
    }
    const row = await pool.query(
      `
      SELECT payload_enc_b64, iv_b64, tag_b64, updated_at
      FROM encrypted_sensitive_store
      WHERE scope = $1
        AND record_type = $2
        AND record_key = $3
      LIMIT 1
      `,
      [scope, recordType, recordKey]
    );
    if (!row.rows.length) return res.status(404).json({ error: 'Record not found' });
    const decrypted = decryptPayload({
      payload_enc_b64: row.rows[0].payload_enc_b64,
      iv_b64: row.rows[0].iv_b64,
      tag_b64: row.rows[0].tag_b64
    });
    return res.json({
      ok: true,
      scope,
      recordType,
      recordKey,
      updatedAt: row.rows[0].updated_at,
      data: decrypted
    });
  } catch (_) {
    return res.status(500).json({ error: 'Failed to read sensitive data' });
  }
});

app.get('/api/leads/assignment-board', authMiddleware, async (req, res) => {
  try {
    if (!hasAnyRole(req, ['ADMIN', 'TEAM'])) {
      return res.status(403).json({ error: 'Admin or Team role required' });
    }
    const scope = sanitizeScope(req.query.scope);
    const requestedTeam = String(req.query.team || '').trim();
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    const params = requestedTeam ? [scope, requestedTeam] : [scope];
    const teamSql = requestedTeam ? ' AND l.jfa_team = $2 ' : '';
    const teamFaSql = requestedTeam ? ' AND f.team = $2 ' : '';

    const [leadRows, faRows] = await Promise.all([
      pool.query(
        `
        SELECT
          l.lead_id,
          l.jfa_name,
          l.jfa_team,
          l.created_at,
          l.payment_status,
          l.fa_assigned_user_key,
          l.fa_assigned_name,
          (EXTRACT(EPOCH FROM (NOW() - l.created_at)) / 3600.0)::numeric(10,2) AS age_hours,
          ((EXTRACT(EPOCH FROM (NOW() - l.created_at)) / 3600.0) >= $${requestedTeam ? '3' : '2'}) AS sla_breached
        FROM normalized_leads l
        WHERE l.scope = $1
          ${teamSql}
          AND l.payment_status = 'Pending'
        ORDER BY l.created_at ASC
        LIMIT 500
        `,
        requestedTeam ? [scope, requestedTeam, LEAD_ASSIGN_SLA_HOURS] : [scope, LEAD_ASSIGN_SLA_HOURS]
      ),
      pool.query(
        `
        SELECT
          f.user_key,
          f.full_name,
          f.team,
          count(l.lead_id)::int AS pending_assigned
        FROM normalized_fa_register f
        LEFT JOIN normalized_leads l
          ON l.scope = f.scope
         AND l.fa_assigned_user_key = f.user_key
         AND l.payment_status = 'Pending'
        WHERE f.scope = $1
          ${teamFaSql}
          AND f.is_active = true
        GROUP BY f.user_key, f.full_name, f.team
        ORDER BY pending_assigned ASC, f.full_name ASC
        `,
        params
      )
    ]);

    return res.json({
      ok: true,
      scope,
      team: requestedTeam || null,
      faCapacityLimit: FA_ASSIGN_MAX_PENDING_PER_FA,
      leadSlaHours: LEAD_ASSIGN_SLA_HOURS,
      pendingLeads: leadRows.rows || [],
      faCapacity: (faRows.rows || []).map((row) => ({
        ...row,
        atCapacity: safeInt(row.pending_assigned, 0) >= FA_ASSIGN_MAX_PENDING_PER_FA
      }))
    });
  } catch (_) {
    return res.status(500).json({ error: 'Failed to load assignment board' });
  }
});

app.post('/api/leads/auto-assign', authMiddleware, async (req, res) => {
  try {
    if (!hasAnyRole(req, ['ADMIN', 'TEAM'])) {
      return res.status(403).json({ error: 'Admin or Team role required' });
    }
    const scope = sanitizeScope(req.body?.scope);
    const requestedTeam = String(req.body?.team || '').trim();
    const maxAssignments = Math.max(1, Math.min(500, safeInt(req.body?.maxAssignments, 100)));
    if (!isSafeScope(scope)) return res.status(400).json({ error: 'Invalid scope' });
    const actorCtx = getActorContext(req);
    const { ipAddress, userAgent } = getRequestMeta(req);

    const teamFilterSql = requestedTeam ? ' AND l.jfa_team = $2 ' : '';
    const leadParams = requestedTeam ? [scope, requestedTeam, maxAssignments] : [scope, maxAssignments];
    const faParams = requestedTeam ? [scope, requestedTeam] : [scope];

    const [pendingLeadsRes, faRes] = await Promise.all([
      pool.query(
        `
        SELECT l.lead_id, l.jfa_team, l.created_at,
               (EXTRACT(EPOCH FROM (NOW() - l.created_at)) / 3600.0) AS age_hours
        FROM normalized_leads l
        WHERE l.scope = $1
          ${teamFilterSql}
          AND l.payment_status = 'Pending'
          AND l.fa_assigned_user_key = ''
        ORDER BY l.lead_date ASC, l.created_at ASC
        LIMIT $${requestedTeam ? '3' : '2'}
        `,
        leadParams
      ),
      pool.query(
        `
        SELECT f.user_key, f.full_name, f.team
        FROM normalized_fa_register f
        WHERE f.scope = $1
          ${requestedTeam ? ' AND f.team = $2 ' : ''}
          AND f.is_active = true
        ORDER BY f.full_name ASC
        `,
        faParams
      )
    ]);

    const pendingLeads = pendingLeadsRes.rows || [];
    const fas = faRes.rows || [];
    if (!pendingLeads.length) {
      return res.json({ ok: true, assigned: 0, reason: 'No pending unassigned leads found.' });
    }
    if (!fas.length) {
      return res.status(400).json({ error: 'No active FA available for assignment.' });
    }

    const loadRes = await pool.query(
      `
      SELECT fa_assigned_user_key AS user_key, count(*)::int AS total
      FROM normalized_leads
      WHERE scope = $1
        AND payment_status = 'Pending'
        AND fa_assigned_user_key <> ''
      GROUP BY fa_assigned_user_key
      `,
      [scope]
    );
    const currentLoad = new Map(loadRes.rows.map((row) => [String(row.user_key || ''), safeInt(row.total, 0)]));
    const faList = fas.map((fa) => ({
      userKey: String(fa.user_key || ''),
      name: String(fa.full_name || fa.user_key || ''),
      load: currentLoad.get(String(fa.user_key || '')) || 0
    }));

    const { payload } = await loadAppState(scope);
    const leadRecords = parsePayloadArray(payload, 'leadRecords');
    const leadIndexByLeadId = new Map(leadRecords.map((lead, index) => [String(lead?.leadId || '').trim(), index]));
    const assignedAt = new Date().toISOString();

    let assigned = 0;
    let skippedCapacity = 0;
    let slaBreachedAssigned = 0;
    for (const lead of pendingLeads) {
      faList.sort((a, b) => a.load - b.load || a.name.localeCompare(b.name));
      const withinCap = faList.filter((fa) => fa.load < FA_ASSIGN_MAX_PENDING_PER_FA);
      const target = (withinCap[0] || faList[0]);
      if (!target || !target.userKey) continue;
      if (target.load >= FA_ASSIGN_MAX_PENDING_PER_FA) skippedCapacity += 1;

      await pool.query(
        `
        UPDATE normalized_leads
        SET fa_assigned_user_key = $1,
            fa_assigned_name = $2,
            fa_assigned_at = $3,
            route_reason = 'auto-balanced'
        WHERE scope = $4
          AND lead_id = $5
          AND fa_assigned_user_key = ''
        `,
        [target.userKey, target.name, assignedAt, scope, String(lead.lead_id || '')]
      );

      const idx = leadIndexByLeadId.get(String(lead.lead_id || ''));
      if (Number.isInteger(idx) && idx >= 0) {
        const item = leadRecords[idx] || {};
        item.assignedFaUserKey = target.userKey;
        item.assignedFaName = target.name;
        item.assignedFaAt = assignedAt;
        item.routeReason = 'auto-balanced';
        leadRecords[idx] = item;
      }
      if (Number(lead.age_hours || 0) >= LEAD_ASSIGN_SLA_HOURS) {
        slaBreachedAssigned += 1;
      }
      target.load += 1;
      assigned += 1;
    }

    if (assigned > 0) {
      writePayloadJson(payload, 'leadRecords', leadRecords);
      await saveAppState(scope, payload);
    }

    await appendImmutableAudit({
      scope,
      actor: actorCtx.actor,
      actorRole: actorCtx.role,
      sessionId: actorCtx.sessionId,
      action: 'LEAD_AUTO_ASSIGN',
      details: `assigned=${assigned};team=${requestedTeam || 'ALL'}`,
      source: 'api',
      ipAddress,
      userAgent
    });

    return res.json({
      ok: true,
      assigned,
      skippedCapacity,
      slaBreachedAssigned,
      faCapacityLimit: FA_ASSIGN_MAX_PENDING_PER_FA,
      leadSlaHours: LEAD_ASSIGN_SLA_HOURS,
      scope,
      team: requestedTeam || null
    });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to auto-assign leads' });
  }
});

app.get('/api/reminders/list', authMiddleware, async (req, res) => {
  try {
    const scope = sanitizeScope(req.query.scope);
    const userKey = normalizeKey(req.query.userKey);
    if (!isSafeScope(scope) || !userKey) {
      return res.status(400).json({ error: 'Invalid scope/userKey' });
    }
    const result = await pool.query(
      `
      SELECT id, title, message, reminder_type, due_at, created_at
      FROM reminder_events
      WHERE scope = $1
        AND user_key = $2
      ORDER BY due_at DESC
      LIMIT 100
      `,
      [scope, userKey]
    );
    return res.json({ ok: true, items: result.rows });
  } catch (error) {
    return res.status(500).json({ error: 'Failed to list reminders' });
  }
});

if (SERVE_STATIC) {
  app.use(express.static(STATIC_DIR));
  app.get('/', (_req, res) => {
    res.sendFile(path.join(STATIC_DIR, 'JFA_Register.html'));
  });
}

const TOKEN_CLEANUP_INTERVAL_MS = 60 * 60 * 1000;
async function cleanupExpiredTokens() {
  await pool.query(
    `DELETE FROM password_reset_tokens WHERE used_at IS NOT NULL OR expires_at < NOW()`
  );
}

async function cleanupOldAuditAndSnapshots() {
  await pool.query(
    `
    DELETE FROM immutable_audit_log
    WHERE created_at < NOW() - ($1::text || ' days')::interval
    `,
    [String(APP_AUDIT_RETENTION_DAYS)]
  );
  await pool.query(
    `
    DELETE FROM app_state_snapshots
    WHERE created_at < NOW() - ($1::text || ' days')::interval
    `,
    [String(APP_BACKUP_RETENTION_DAYS)]
  );
  await pool.query(
    `
    DELETE FROM reminder_events
    WHERE created_at < NOW() - interval '30 days'
    `
  );
  await pool.query(
    `
    DELETE FROM auth_login_attempts
    WHERE updated_at < NOW() - interval '30 days'
       OR (locked_until IS NOT NULL AND locked_until < NOW() - interval '1 day')
    `
  );
  await pool.query(
    `
    DELETE FROM auth_sessions
    WHERE revoked_at IS NOT NULL
       OR expires_at < NOW() - interval '1 day'
       OR last_seen_at < NOW() - ($1::text || ' seconds')::interval
    `,
    [String(Math.max(SESSION_IDLE_TIMEOUT_SECONDS * 3, 24 * 60 * 60))]
  );
  await pool.query(
    `
    DELETE FROM smtp_outbox
    WHERE (status = 'sent' AND sent_at < NOW() - interval '30 days')
       OR (status = 'dead' AND created_at < NOW() - interval '90 days')
    `
  );
}

async function createScheduledSnapshots() {
  const result = await pool.query(
    `SELECT scope, payload_enc_b64, iv_b64, tag_b64 FROM app_state`
  );
  for (const row of result.rows) {
    await pool.query(
      `
      INSERT INTO app_state_snapshots (scope, payload_enc_b64, iv_b64, tag_b64, source)
      VALUES ($1, $2, $3, $4, 'scheduled')
      `,
      [row.scope, row.payload_enc_b64, row.iv_b64, row.tag_b64]
    );
  }
}

function normalizeKey(value) {
  return String(value || '').trim().toLowerCase();
}

function parseAppointmentDateTime(dateValue, timeValue) {
  const d = String(dateValue || '').trim();
  const t = String(timeValue || '').trim();
  if (!d || !t) return null;
  const dt = new Date(`${d}T${t}`);
  if (Number.isNaN(dt.getTime())) return null;
  return dt;
}

async function scanAndPersistReminderEvents() {
  const rows = await pool.query(`SELECT scope, payload_enc_b64, iv_b64, tag_b64 FROM app_state`);
  const now = new Date();
  const todayIso = now.toISOString().slice(0, 10);

  for (const row of rows.rows) {
    const payload = decryptPayload(row);
    const appointments = parsePayloadJson(payload, 'jfaAppointments', []);
    if (!Array.isArray(appointments) || !appointments.length) continue;
    for (const item of appointments) {
      const userKey = normalizeKey(item?.jfaName || item?.jfaUsername || '');
      const dueAt = parseAppointmentDateTime(item?.date, item?.time);
      if (!userKey || !dueAt) continue;
      const leadId = String(item?.leadId || item?.id || '').trim() || 'LID';
      const diffMinutes = Math.round((dueAt.getTime() - now.getTime()) / 60000);
      const isMorningReminder = String(item?.date || '').trim() === todayIso;
      const isHourReminder = diffMinutes >= 40 && diffMinutes <= 70;
      const candidates = [];
      if (isMorningReminder) {
        candidates.push({
          type: 'MORNING',
          key: `MORNING-${leadId}-${todayIso}`,
          dueAt,
          title: 'Appointment Reminder',
          message: `You have an appointment today at ${item.time || '—'} (LID ${leadId}).`
        });
      }
      if (isHourReminder) {
        candidates.push({
          type: 'ONE_HOUR',
          key: `ONE_HOUR-${leadId}-${item.date || ''}-${item.time || ''}`,
          dueAt,
          title: 'Appointment in 1 hour',
          message: `Client appointment is coming up at ${item.time || '—'} (LID ${leadId}).`
        });
      }
      for (const reminder of candidates) {
        await pool.query(
          `
          INSERT INTO reminder_events
            (scope, user_key, reminder_type, reminder_key, title, message, due_at)
          VALUES
            ($1, $2, $3, $4, $5, $6, $7)
          ON CONFLICT (scope, user_key, reminder_key) DO NOTHING
          `,
          [row.scope, userKey, reminder.type, reminder.key, reminder.title, reminder.message, reminder.dueAt.toISOString()]
        );
      }
    }
  }
}

async function rebuildNormalizedTablesFromState() {
  const rows = await pool.query(`SELECT scope, payload_enc_b64, iv_b64, tag_b64 FROM app_state`);
  for (const row of rows.rows) {
    const payload = decryptPayload(row);
    await syncNormalizedState(row.scope, payload);
  }
}

async function runQualityAlertScan() {
  const scopeRows = await pool.query(`SELECT scope FROM app_state`);
  for (const row of scopeRows.rows) {
    const scope = String(row.scope || '').trim();
    if (!scope) continue;
    const quality = await pool.query(
      `
      SELECT
        count(*)::int AS total_leads,
        count(*) FILTER (WHERE has_geotag = false)::int AS missing_geotag,
        count(*) FILTER (WHERE has_signature = false)::int AS missing_signature,
        count(*) FILTER (WHERE payment_status = 'Pending' AND fa_assigned_user_key = '')::int AS pending_without_fa
      FROM normalized_leads
      WHERE scope = $1
      `,
      [scope]
    );
    const summary = quality.rows?.[0] || {};
    const issueCount =
      safeInt(summary.missing_geotag, 0)
      + safeInt(summary.missing_signature, 0)
      + safeInt(summary.pending_without_fa, 0);
    if (issueCount <= 0) continue;

    const admins = await pool.query(
      `
      SELECT user_key
      FROM normalized_users
      WHERE scope = $1
        AND role = 'ADMIN'
        AND is_active = true
      `,
      [scope]
    );
    const nowIso = new Date().toISOString();
    const reminderKey = `QUALITY-${new Date().toISOString().slice(0, 13)}`;
    const message = `Quality alert: ${summary.missing_geotag || 0} missing geotags, ${summary.missing_signature || 0} missing signatures, ${summary.pending_without_fa || 0} pending leads without FA assignment.`;
    for (const admin of admins.rows || []) {
      const userKey = normalizeKey(admin.user_key);
      if (!userKey) continue;
      await pool.query(
        `
        INSERT INTO reminder_events
          (scope, user_key, reminder_type, reminder_key, title, message, due_at)
        VALUES
          ($1, $2, 'QUALITY', $3, 'Data Quality Alert', $4, $5)
        ON CONFLICT (scope, user_key, reminder_key) DO NOTHING
        `,
        [scope, userKey, reminderKey, message, nowIso]
      );
    }
  }
}

ensureSchema()
  .then(() => {
    cleanupExpiredTokens().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Token cleanup failed at startup.');
    });
    createScheduledSnapshots().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Initial snapshot creation failed.');
    });
    rebuildNormalizedTablesFromState().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Initial normalized-state sync failed.');
    });
    scanAndPersistReminderEvents().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Initial reminder scan failed.');
    });
    dispatchSmtpOutboxOnce().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Initial SMTP outbox dispatch failed.');
    });
    runQualityAlertScan().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Initial quality alert scan failed.');
    });
    cleanupOldAuditAndSnapshots().catch(() => {
      // eslint-disable-next-line no-console
      console.warn('Initial cleanup failed.');
    });
    setInterval(() => {
      cleanupExpiredTokens().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled token cleanup failed.');
      });
    }, TOKEN_CLEANUP_INTERVAL_MS);
    setInterval(() => {
      createScheduledSnapshots().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled snapshot creation failed.');
      });
    }, APP_BACKUP_INTERVAL_MINUTES * 60 * 1000);
    setInterval(() => {
      rebuildNormalizedTablesFromState().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled normalized-state sync failed.');
      });
    }, 30 * 60 * 1000);
    setInterval(() => {
      scanAndPersistReminderEvents().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled reminder scan failed.');
      });
    }, 5 * 60 * 1000);
    setInterval(() => {
      dispatchSmtpOutboxOnce().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled SMTP outbox dispatch failed.');
      });
    }, 60 * 1000);
    setInterval(() => {
      runQualityAlertScan().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled quality alert scan failed.');
      });
    }, 15 * 60 * 1000);
    setInterval(() => {
      cleanupOldAuditAndSnapshots().catch(() => {
        // eslint-disable-next-line no-console
        console.warn('Scheduled cleanup failed.');
      });
    }, 12 * 60 * 60 * 1000);
    app.listen(PORT, () => {
      // eslint-disable-next-line no-console
      console.log(`Secure API listening on http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error('Failed to start server:', err.message);
    process.exit(1);
  });
