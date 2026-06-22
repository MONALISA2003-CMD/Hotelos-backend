// auth.js — Real server-side authentication.
// Unlike the client-side PBKDF2 version in the frontend, this is genuinely secure:
// the password hash and verification logic live on the server, never in code the
// browser can read. This is the thing that actually closes the gap from before.
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { query } = require('./db');

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET must be set to a random string of 32+ characters. Generate one with: openssl rand -hex 32');
  process.exit(1);
}

const SALT_ROUNDS = 12; // bcrypt cost factor — 12 is the current recommended baseline (2026)
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;
const SESSION_HOURS = 8;

async function hashPassword(plain) {
  return bcrypt.hash(plain, SALT_ROUNDS);
}

async function verifyPassword(plain, hash) {
  return bcrypt.compare(plain, hash);
}

function issueToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role, branch_id: user.branch_id },
    JWT_SECRET,
    { expiresIn: `${SESSION_HOURS}h` }
  );
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (e) {
    return null;
  }
}

// Express middleware — attaches req.user if a valid token is present, else 401s.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing or invalid authorization header' });
  const payload = verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'Invalid or expired session' });
  req.user = payload;
  next();
}

// Role-gate middleware factory — usage: requireRole('admin','manager')
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (req.user.role === 'admin') return next(); // admin bypasses all role gates
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: `This action requires one of: ${allowedRoles.join(', ')}` });
    }
    next();
  };
}

async function isLocked(username) {
  const { rows } = await query('SELECT failed_attempts, locked_until FROM users WHERE username=$1', [username]);
  if (!rows[0]) return false;
  const { failed_attempts, locked_until } = rows[0];
  if (failed_attempts >= MAX_FAILED_ATTEMPTS && locked_until && new Date(locked_until) > new Date()) {
    return true;
  }
  return false;
}

async function recordFailedAttempt(username) {
  const { rows } = await query('SELECT failed_attempts, locked_until FROM users WHERE username=$1', [username]);
  if (!rows[0]) return; // don't reveal whether the username exists
  const stale = !rows[0].locked_until || new Date(rows[0].locked_until) < new Date(Date.now() - LOCKOUT_MINUTES * 60000 * 2);
  const newCount = stale ? 1 : rows[0].failed_attempts + 1;
  const lockedUntil = newCount >= MAX_FAILED_ATTEMPTS ? new Date(Date.now() + LOCKOUT_MINUTES * 60000) : rows[0].locked_until;
  await query('UPDATE users SET failed_attempts=$1, locked_until=$2 WHERE username=$3', [newCount, lockedUntil, username]);
  return newCount;
}

async function clearFailedAttempts(username) {
  await query('UPDATE users SET failed_attempts=0, locked_until=NULL WHERE username=$1', [username]);
}

module.exports = {
  hashPassword, verifyPassword, issueToken, verifyToken,
  requireAuth, requireRole, isLocked, recordFailedAttempt, clearFailedAttempts,
  SALT_ROUNDS, MAX_FAILED_ATTEMPTS, LOCKOUT_MINUTES
};
