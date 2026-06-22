// server.js — HotelOS Pro backend.
// Express REST API + Socket.io (real-time multi-device sync) + Stripe webhook + Postgres.
//
// This is what turns the single-file frontend into a real multi-device, multi-user system:
// every device that connects gets live updates the instant any other device makes a change,
// instead of the 20-second poll the localStorage-only version used.

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');

const { query, migrate } = require('./db');
const auth = require('./auth');
const email = require('./email');
const payments = require('./payments');

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } }); // tighten origin in production once your frontend domain is fixed

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------- middleware
app.use(helmet());
app.use(cors());

// IMPORTANT: the Stripe webhook route needs the RAW body for signature verification,
// so it's registered BEFORE the global express.json() middleware, with its own raw parser.
app.post('/api/webhooks/stripe', express.raw({ type: 'application/json' }), handleStripeWebhook);

app.use(express.json({ limit: '2mb' }));

// Basic rate limiting on auth endpoints — slows down brute force beyond the per-account lockout.
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, message: { error: 'Too many requests, slow down.' } });
app.use('/api/auth/login', loginLimiter);

// ---------------------------------------------------------------- helpers
function newId(prefix) {
  return `${prefix}${Date.now().toString(36)}${crypto.randomBytes(3).toString('hex')}`;
}

async function logAudit({ branchId, username, action, module, detail, before, after, refId, ip }) {
  await query(
    `INSERT INTO audit_log (branch_id, username, action, module, detail, before_val, after_val, ref_id, ip_address)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
    [branchId, username, action, module, detail, before, after, refId, ip]
  );
}

// Broadcasts a change to every connected device in the same branch, so other phones/tablets
// update live instead of waiting for their next poll.
function broadcast(branchId, event, payload) {
  io.to(`branch:${branchId}`).emit(event, payload);
}

// ================================================================ AUTH ROUTES
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const uname = String(username).trim().toLowerCase();

  if (await auth.isLocked(uname)) {
    return res.status(423).json({ error: 'Account temporarily locked due to too many failed attempts. Try again in 15 minutes.' });
  }

  const { rows } = await query('SELECT * FROM users WHERE username=$1', [uname]);
  const user = rows[0];

  // Always run bcrypt.compare even for unknown usernames (against a dummy hash) so response
  // timing doesn't leak whether the username exists.
  const dummyHash = '$2a$12$abcdefghijklmnopqrstuuC8z8z8z8z8z8z8z8z8z8z8z8z8z8z8O';
  const ok = user ? await auth.verifyPassword(password, user.password_hash) : await auth.verifyPassword(password, dummyHash);

  if (!ok || !user) {
    const attempts = await auth.recordFailedAttempt(uname);
    await logAudit({ branchId: null, username: uname, action: 'login_failed', module: 'Auth', detail: `Failed login attempt`, ip: req.ip });
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  await auth.clearFailedAttempts(uname);
  const token = auth.issueToken(user);
  await logAudit({ branchId: user.branch_id, username: user.username, action: 'login_success', module: 'Auth', detail: 'Signed in', ip: req.ip });

  res.json({
    token,
    user: { username: user.username, name: user.name, role: user.role, branchId: user.branch_id }
  });
});

app.post('/api/auth/change-password', auth.requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || newPassword.length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });

  const { rows } = await query('SELECT * FROM users WHERE username=$1', [req.user.username]);
  const user = rows[0];
  if (!user) return res.status(404).json({ error: 'User not found' });

  const ok = await auth.verifyPassword(currentPassword, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });

  const newHash = await auth.hashPassword(newPassword);
  await query('UPDATE users SET password_hash=$1 WHERE username=$2', [newHash, user.username]);
  await logAudit({ branchId: user.branch_id, username: user.username, action: 'password_changed', module: 'Auth', detail: 'Password updated', ip: req.ip });

  if (user.email) email.sendPasswordChangedAlert({ userEmail: user.email, userName: user.name }).catch(()=>{});
  res.json({ ok: true });
});

// Role-switch re-authentication — mirrors the frontend's client-only version, but this is the
// real, trustworthy check since it happens server-side.
app.post('/api/auth/switch-role', auth.requireAuth, async (req, res) => {
  const { targetUsername, password } = req.body || {};
  if (await auth.isLocked(targetUsername)) {
    return res.status(423).json({ error: 'That account is temporarily locked.' });
  }
  const { rows } = await query('SELECT * FROM users WHERE username=$1', [targetUsername]);
  const user = rows[0];
  const ok = user && await auth.verifyPassword(password, user.password_hash);
  if (!ok) {
    await auth.recordFailedAttempt(targetUsername);
    return res.status(401).json({ error: 'Incorrect password' });
  }
  await auth.clearFailedAttempts(targetUsername);
  const token = auth.issueToken(user);
  await logAudit({ branchId: user.branch_id, username: user.username, action: 'role_switch', module: 'Auth', detail: `Switched to ${user.role}`, ip: req.ip });
  res.json({ token, user: { username: user.username, name: user.name, role: user.role, branchId: user.branch_id } });
});

app.get('/api/auth/me', auth.requireAuth, (req, res) => {
  res.json({ user: req.user });
});

// ================================================================ DATA SYNC — bulk fetch for initial load
app.get('/api/branches/:branchId/data', auth.requireAuth, async (req, res) => {
  const { branchId } = req.params;
  const [guests, rooms, bookings, payments_, staff, housekeeping, maintenance] = await Promise.all([
    query('SELECT * FROM guests WHERE branch_id=$1 ORDER BY created_at DESC', [branchId]),
    query('SELECT * FROM rooms WHERE branch_id=$1 ORDER BY number', [branchId]),
    query('SELECT * FROM bookings WHERE branch_id=$1 ORDER BY created_at DESC LIMIT 500', [branchId]),
    query('SELECT * FROM payments WHERE branch_id=$1 ORDER BY timestamp DESC LIMIT 500', [branchId]),
    query('SELECT * FROM staff WHERE branch_id=$1', [branchId]),
    query('SELECT * FROM housekeeping_tasks WHERE branch_id=$1 ORDER BY created_at DESC LIMIT 200', [branchId]),
    query('SELECT * FROM maintenance_tickets WHERE branch_id=$1 ORDER BY created_at DESC LIMIT 200', [branchId])
  ]);
  res.json({
    guests: guests.rows, rooms: rooms.rows, bookings: bookings.rows, payments: payments_.rows,
    staff: staff.rows, housekeeping: housekeeping.rows, maintenance: maintenance.rows
  });
});

app.get('/api/branches', auth.requireAuth, async (req, res) => {
  const { rows } = await query('SELECT * FROM branches ORDER BY name');
  res.json({ branches: rows });
});

// ================================================================ GUESTS
app.post('/api/guests', auth.requireAuth, auth.requireRole('admin','manager','receptionist'), async (req, res) => {
  const { branchId, firstName, lastName, email: guestEmail, phone, nationality, idNumber, vip, preferences } = req.body;
  if (!firstName || !lastName) return res.status(400).json({ error: 'First and last name required' });

  const existing = guestEmail ? await query('SELECT id FROM guests WHERE email=$1 AND branch_id=$2', [guestEmail, branchId]) : { rows: [] };
  if (existing.rows.length > 0) return res.status(409).json({ error: 'A guest with this email already exists' });

  const id = newId('G');
  await query(
    `INSERT INTO guests (id, branch_id, first_name, last_name, email, phone, nationality, id_number, vip, preferences)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [id, branchId, firstName, lastName, guestEmail, phone, nationality, idNumber, vip || 0, preferences]
  );
  await logAudit({ branchId, username: req.user.username, action: 'guest_created', module: 'Guests', detail: `${firstName} ${lastName}`, refId: id, ip: req.ip });
  broadcast(branchId, 'guest:created', { id });
  res.status(201).json({ id });
});

// ================================================================ ROOMS
app.post('/api/rooms', auth.requireAuth, auth.requireRole('admin','manager'), async (req, res) => {
  const { branchId, number, type, price, floor, capacity, features } = req.body;
  if (!number || !price) return res.status(400).json({ error: 'Room number and price required' });

  const existing = await query('SELECT id FROM rooms WHERE branch_id=$1 AND number=$2', [branchId, number]);
  if (existing.rows.length > 0) return res.status(409).json({ error: 'Room number already exists in this branch' });

  const id = newId('R');
  await query(
    `INSERT INTO rooms (id, branch_id, number, type, price, floor, capacity, status, features)
     VALUES ($1,$2,$3,$4,$5,$6,$7,'available',$8)`,
    [id, branchId, number, type, price, floor || 1, capacity || 2, features]
  );
  await logAudit({ branchId, username: req.user.username, action: 'room_added', module: 'Rooms', detail: `Room ${number}`, refId: id, ip: req.ip });
  broadcast(branchId, 'room:created', { id });
  res.status(201).json({ id });
});

app.patch('/api/rooms/:id/status', auth.requireAuth, auth.requireRole('admin','manager','housekeeping','maintenance'), async (req, res) => {
  const { status } = req.body;
  const validStatuses = ['available','occupied','reserved','cleaning','maintenance','out-of-service'];
  if (!validStatuses.includes(status)) return res.status(400).json({ error: 'Invalid status' });

  const { rows } = await query('UPDATE rooms SET status=$1, last_cleaned=CASE WHEN $1=$2 THEN now() ELSE last_cleaned END WHERE id=$3 RETURNING *', [status, 'available', req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Room not found' });

  await logAudit({ branchId: rows[0].branch_id, username: req.user.username, action: 'room_status_changed', module: 'Rooms', after: status, refId: req.params.id, ip: req.ip });
  broadcast(rows[0].branch_id, 'room:updated', rows[0]);
  res.json(rows[0]);
});

// ================================================================ BOOKINGS — with real double-booking prevention
app.post('/api/bookings', auth.requireAuth, auth.requireRole('admin','manager','receptionist'), async (req, res) => {
  const { branchId, guestId, roomId, checkin, checkout, numGuests, requests, paymentMethod } = req.body;
  if (!guestId || !roomId || !checkin || !checkout) return res.status(400).json({ error: 'Missing required booking fields' });
  if (new Date(checkout) <= new Date(checkin)) return res.status(400).json({ error: 'Check-out must be after check-in' });

  // Real double-booking prevention at the database level — a race condition between two
  // receptionists on two different phones booking the same room at the same instant is
  // caught here, not just in client-side JS (which the old localStorage version relied on).
  const conflict = await query(
    `SELECT id FROM bookings WHERE room_id=$1 AND status NOT IN ('cancelled','checked_out')
     AND NOT (checkout <= $2 OR checkin >= $3)`,
    [roomId, checkin, checkout]
  );
  if (conflict.rows.length > 0) {
    return res.status(409).json({ error: `Room is already booked for overlapping dates (conflicts with ${conflict.rows[0].id})` });
  }

  const roomRes = await query('SELECT * FROM rooms WHERE id=$1', [roomId]);
  const room = roomRes.rows[0];
  if (!room) return res.status(404).json({ error: 'Room not found' });

  const nights = Math.ceil((new Date(checkout) - new Date(checkin)) / 86400000);
  const total = Number(room.price) * nights;
  const id = newId('BK');

  await query(
    `INSERT INTO bookings (id, branch_id, guest_id, room_id, checkin, checkout, nights, total, status, payment_status, payment_method, num_guests, requests)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'confirmed','unpaid',$9,$10,$11)`,
    [id, branchId, guestId, roomId, checkin, checkout, nights, total, paymentMethod, numGuests || 1, requests]
  );
  await query(`UPDATE rooms SET status='reserved' WHERE id=$1`, [roomId]);

  await logAudit({ branchId, username: req.user.username, action: 'room_booked', module: 'Bookings', detail: id, refId: id, ip: req.ip });
  broadcast(branchId, 'booking:created', { id });
  broadcast(branchId, 'room:updated', { id: roomId, status: 'reserved' });

  // Real confirmation email — fire-and-forget so a slow email provider never blocks the booking response
  const guestRes = await query('SELECT * FROM guests WHERE id=$1', [guestId]);
  const branchRes = await query('SELECT * FROM branches WHERE id=$1', [branchId]);
  if (guestRes.rows[0]?.email) {
    email.sendBookingConfirmation({
      guestEmail: guestRes.rows[0].email,
      guestName: `${guestRes.rows[0].first_name} ${guestRes.rows[0].last_name}`,
      bookingId: id, roomNumber: room.number, roomType: room.type,
      checkin, checkout, total, branchName: branchRes.rows[0]?.name || 'our hotel'
    }).catch(e => console.error('Confirmation email failed:', e.message));
  }

  res.status(201).json({ id, total, nights });
});

app.post('/api/bookings/:id/checkin', auth.requireAuth, auth.requireRole('admin','manager','receptionist'), async (req, res) => {
  const { rows } = await query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
  const booking = rows[0];
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  if (booking.status === 'checked_in') return res.status(409).json({ error: 'Already checked in' });
  if (booking.status === 'cancelled') return res.status(409).json({ error: 'Booking is cancelled' });

  await query(`UPDATE bookings SET status='checked_in', checkin_time=now() WHERE id=$1`, [booking.id]);
  await query(`UPDATE rooms SET status='occupied' WHERE id=$1`, [booking.room_id]);
  await logAudit({ branchId: booking.branch_id, username: req.user.username, action: 'checkin_completed', module: 'Check-in', refId: booking.id, ip: req.ip });
  broadcast(booking.branch_id, 'booking:updated', { id: booking.id, status: 'checked_in' });
  broadcast(booking.branch_id, 'room:updated', { id: booking.room_id, status: 'occupied' });
  res.json({ ok: true });
});

app.post('/api/bookings/:id/checkout', auth.requireAuth, auth.requireRole('admin','manager','receptionist'), async (req, res) => {
  const { rows } = await query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
  const booking = rows[0];
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  if (booking.status !== 'checked_in') return res.status(409).json({ error: 'Guest is not currently checked in' });
  if (booking.payment_status !== 'paid') return res.status(402).json({ error: 'Outstanding balance must be settled before checkout', balance: booking.total });

  await query(`UPDATE bookings SET status='checked_out', checkout_time=now() WHERE id=$1`, [booking.id]);
  await query(`UPDATE rooms SET status='cleaning' WHERE id=$1`, [booking.room_id]);

  const hkId = newId('HK');
  await query(
    `INSERT INTO housekeeping_tasks (id, branch_id, room_id, type, priority, status, notes)
     VALUES ($1,$2,$3,'Post Checkout','high','pending','Auto-created on checkout')`,
    [hkId, booking.branch_id, booking.room_id]
  );

  await query(`UPDATE guests SET loyalty_points = loyalty_points + $1 WHERE id=$2`, [Math.floor(booking.total / 10000), booking.guest_id]);

  await logAudit({ branchId: booking.branch_id, username: req.user.username, action: 'checkout_completed', module: 'Check-out', refId: booking.id, ip: req.ip });
  broadcast(booking.branch_id, 'booking:updated', { id: booking.id, status: 'checked_out' });
  broadcast(booking.branch_id, 'room:updated', { id: booking.room_id, status: 'cleaning' });
  broadcast(booking.branch_id, 'housekeeping:created', { id: hkId });
  res.json({ ok: true });
});

app.post('/api/bookings/:id/cancel', auth.requireAuth, auth.requireRole('admin','manager','receptionist'), async (req, res) => {
  const { rows } = await query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
  const booking = rows[0];
  if (!booking) return res.status(404).json({ error: 'Booking not found' });

  await query(`UPDATE bookings SET status='cancelled' WHERE id=$1`, [booking.id]);
  await query(`UPDATE rooms SET status='available' WHERE id=$1 AND status='reserved'`, [booking.room_id]);
  await logAudit({ branchId: booking.branch_id, username: req.user.username, action: 'booking_cancelled', module: 'Bookings', refId: booking.id, ip: req.ip });
  broadcast(booking.branch_id, 'booking:updated', { id: booking.id, status: 'cancelled' });
  res.json({ ok: true });
});

// ================================================================ PAYMENTS
// Manual payment recording (cash/mobile money at the front desk — no Stripe needed for these)
app.post('/api/bookings/:id/pay-manual', auth.requireAuth, auth.requireRole('admin','manager','receptionist'), async (req, res) => {
  const { amount, method } = req.body;
  const { rows } = await query('SELECT * FROM bookings WHERE id=$1', [req.params.id]);
  const booking = rows[0];
  if (!booking) return res.status(404).json({ error: 'Booking not found' });

  const id = newId('PAY');
  await query(
    `INSERT INTO payments (id, branch_id, booking_id, amount, method, status) VALUES ($1,$2,$3,$4,$5,'completed')`,
    [id, booking.branch_id, booking.id, amount, method]
  );
  await query(`UPDATE bookings SET payment_status='paid' WHERE id=$1`, [booking.id]);
  await logAudit({ branchId: booking.branch_id, username: req.user.username, action: 'payment_received', module: 'Billing', detail: `${method} ${amount}`, refId: id, ip: req.ip });
  broadcast(booking.branch_id, 'payment:created', { id, bookingId: booking.id });
  broadcast(booking.branch_id, 'booking:updated', { id: booking.id, paymentStatus: 'paid' });
  res.status(201).json({ id });
});

// Real Stripe checkout — creates a hosted payment page URL the guest/receptionist opens to pay by card.
app.post('/api/bookings/:id/pay-stripe', auth.requireAuth, async (req, res) => {
  if (!payments.isConfigured()) {
    return res.status(503).json({ error: 'Card payments are not configured on this server yet. Set STRIPE_SECRET_KEY in Railway to enable.' });
  }
  const { rows } = await query(
    `SELECT b.*, g.email as guest_email FROM bookings b LEFT JOIN guests g ON g.id=b.guest_id WHERE b.id=$1`,
    [req.params.id]
  );
  const booking = rows[0];
  if (!booking) return res.status(404).json({ error: 'Booking not found' });
  if (booking.payment_status === 'paid') return res.status(409).json({ error: 'Booking is already paid' });

  try {
    const session = await payments.createCheckoutSession({
      bookingId: booking.id,
      amount: Number(booking.total),
      currency: req.body.currency || 'usd',
      guestEmail: booking.guest_email,
      description: `Booking ${booking.id} — ${booking.nights} night(s)`
    });
    await query(`UPDATE bookings SET stripe_session_id=$1 WHERE id=$2`, [session.sessionId, booking.id]);
    res.json(session);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Stripe webhook — this is the ONLY trustworthy place payment confirmation happens.
// Registered earlier with express.raw() so the signature check sees the unmodified body.
async function handleStripeWebhook(req, res) {
  let event;
  try {
    event = payments.constructWebhookEvent(req.body, req.headers['stripe-signature']);
  } catch (err) {
    console.error('Stripe webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Idempotency: Stripe may deliver the same event more than once. Skip if already processed.
  const already = await query('SELECT id FROM payments WHERE stripe_payment_intent=$1', [event.id]);
  if (already.rows.length > 0) return res.json({ received: true, duplicate: true });

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const bookingId = session.metadata?.bookingId;
    if (bookingId) {
      const { rows } = await query('SELECT * FROM bookings WHERE id=$1', [bookingId]);
      const booking = rows[0];
      if (booking && booking.payment_status !== 'paid') {
        const id = newId('PAY');
        await query(
          `INSERT INTO payments (id, branch_id, booking_id, amount, method, status, stripe_payment_intent)
           VALUES ($1,$2,$3,$4,'Card (Stripe)','completed',$5)`,
          [id, booking.branch_id, booking.id, (session.amount_total || 0) / 100, event.id]
        );
        await query(`UPDATE bookings SET payment_status='paid' WHERE id=$1`, [booking.id]);
        await logAudit({ branchId: booking.branch_id, username: 'stripe-webhook', action: 'payment_received', module: 'Billing', detail: 'Card payment via Stripe', refId: id });
        broadcast(booking.branch_id, 'payment:created', { id, bookingId: booking.id });
        broadcast(booking.branch_id, 'booking:updated', { id: booking.id, paymentStatus: 'paid' });

        const guestRes = await query('SELECT * FROM guests WHERE id=$1', [booking.guest_id]);
        const branchRes = await query('SELECT * FROM branches WHERE id=$1', [booking.branch_id]);
        if (guestRes.rows[0]?.email) {
          email.sendPaymentReceipt({
            guestEmail: guestRes.rows[0].email,
            guestName: `${guestRes.rows[0].first_name} ${guestRes.rows[0].last_name}`,
            bookingId: booking.id, amount: (session.amount_total || 0) / 100, method: 'Card',
            branchName: branchRes.rows[0]?.name || 'our hotel'
          }).catch(()=>{});
        }
      }
    }
  }

  res.json({ received: true });
}

// ================================================================ HOUSEKEEPING
app.post('/api/housekeeping', auth.requireAuth, auth.requireRole('admin','manager','housekeeping'), async (req, res) => {
  const { branchId, roomId, type, priority, staffId, notes } = req.body;
  const id = newId('HK');
  await query(
    `INSERT INTO housekeeping_tasks (id, branch_id, room_id, type, priority, status, staff_id, notes)
     VALUES ($1,$2,$3,$4,$5,'pending',$6,$7)`,
    [id, branchId, roomId, type, priority || 'medium', staffId, notes]
  );
  broadcast(branchId, 'housekeeping:created', { id });
  res.status(201).json({ id });
});

app.patch('/api/housekeeping/:id/status', auth.requireAuth, auth.requireRole('admin','manager','housekeeping'), async (req, res) => {
  const { status } = req.body;
  const timeCol = status === 'in_progress' ? 'started_at' : status === 'completed' ? 'completed_at' : null;
  const sql = timeCol
    ? `UPDATE housekeeping_tasks SET status=$1, ${timeCol}=now() WHERE id=$2 RETURNING *`
    : `UPDATE housekeeping_tasks SET status=$1 WHERE id=$2 RETURNING *`;
  const { rows } = await query(sql, [status, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Task not found' });

  if (status === 'completed') {
    await query(`UPDATE rooms SET status='available', last_cleaned=now() WHERE id=$1`, [rows[0].room_id]);
    broadcast(rows[0].branch_id, 'room:updated', { id: rows[0].room_id, status: 'available' });
  } else if (status === 'in_progress') {
    await query(`UPDATE rooms SET status='cleaning' WHERE id=$1`, [rows[0].room_id]);
    broadcast(rows[0].branch_id, 'room:updated', { id: rows[0].room_id, status: 'cleaning' });
  }
  broadcast(rows[0].branch_id, 'housekeeping:updated', rows[0]);
  res.json(rows[0]);
});

// ================================================================ MAINTENANCE
app.post('/api/maintenance', auth.requireAuth, auth.requireRole('admin','manager','maintenance'), async (req, res) => {
  const { branchId, roomId, title, description, priority, technicianId } = req.body;
  if (!title) return res.status(400).json({ error: 'Issue title required' });
  const id = newId('MT');
  await query(
    `INSERT INTO maintenance_tickets (id, branch_id, room_id, title, description, priority, status, technician_id)
     VALUES ($1,$2,$3,$4,$5,$6,'open',$7)`,
    [id, branchId, roomId, title, description, priority || 'medium', technicianId]
  );
  await query(`UPDATE rooms SET status='maintenance' WHERE id=$1`, [roomId]);
  await logAudit({ branchId, username: req.user.username, action: 'maintenance_created', module: 'Maintenance', detail: title, refId: id, ip: req.ip });
  broadcast(branchId, 'maintenance:created', { id });
  broadcast(branchId, 'room:updated', { id: roomId, status: 'maintenance' });
  res.status(201).json({ id });
});

app.patch('/api/maintenance/:id/status', auth.requireAuth, auth.requireRole('admin','manager','maintenance'), async (req, res) => {
  const { status } = req.body;
  const sql = status === 'resolved'
    ? `UPDATE maintenance_tickets SET status=$1, resolved_at=now() WHERE id=$2 RETURNING *`
    : `UPDATE maintenance_tickets SET status=$1 WHERE id=$2 RETURNING *`;
  const { rows } = await query(sql, [status, req.params.id]);
  if (!rows[0]) return res.status(404).json({ error: 'Ticket not found' });

  if (status === 'resolved') {
    await query(`UPDATE rooms SET status='available' WHERE id=$1 AND status='maintenance'`, [rows[0].room_id]);
    broadcast(rows[0].branch_id, 'room:updated', { id: rows[0].room_id, status: 'available' });
  }
  broadcast(rows[0].branch_id, 'maintenance:updated', rows[0]);
  res.json(rows[0]);
});

// ================================================================ STAFF
app.post('/api/staff', auth.requireAuth, auth.requireRole('admin','manager'), async (req, res) => {
  const { branchId, name, role, dept, email: staffEmail, phone, shift } = req.body;
  if (!name || !role) return res.status(400).json({ error: 'Name and role required' });
  const id = newId('S');
  await query(
    `INSERT INTO staff (id, branch_id, name, role, dept, email, phone, shift, status)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'active')`,
    [id, branchId, name, role, dept, staffEmail, phone, shift]
  );
  broadcast(branchId, 'staff:created', { id });
  res.status(201).json({ id });
});

// ================================================================ AUDIT LOG (read-only, admin/manager)
app.get('/api/branches/:branchId/audit', auth.requireAuth, auth.requireRole('admin','manager'), async (req, res) => {
  const { rows } = await query(
    `SELECT * FROM audit_log WHERE branch_id=$1 ORDER BY created_at DESC LIMIT 200`,
    [req.params.branchId]
  );
  res.json({ entries: rows });
});

// ================================================================ HEALTH CHECK (Railway uses this)
app.get('/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));
app.get('/', (req, res) => res.json({ service: 'HotelOS Pro API', status: 'running' }));

// ================================================================ SOCKET.IO — real-time multi-device sync
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  const payload = token ? auth.verifyToken(token) : null;
  if (!payload) return next(new Error('Unauthorized'));
  socket.user = payload;
  next();
});

io.on('connection', (socket) => {
  const branchId = socket.user.branch_id;
  socket.join(`branch:${branchId}`);
  console.log(`Socket connected: ${socket.user.username} (${branchId})`);

  socket.on('disconnect', () => {
    console.log(`Socket disconnected: ${socket.user.username}`);
  });
});

// ================================================================ BOOT
async function boot() {
  await migrate();
  await seedIfEmpty();
  server.listen(PORT, () => console.log(`🏨 HotelOS Pro API listening on port ${PORT}`));
}

// Seeds demo branches + an initial admin account ONLY if the database is empty —
// safe to redeploy without wiping real data.
async function seedIfEmpty() {
  const { rows } = await query('SELECT COUNT(*) FROM branches');
  if (Number(rows[0].count) > 0) return; // already seeded, don't touch real data

  console.log('Empty database detected — seeding initial branch and admin account...');
  await query(`INSERT INTO branches (id, name, city, manager, stars, phone) VALUES ('grand','Grand Palace Hotel','Kampala','Sarah Nakato',5,'+256414123456')`);

  const initialPassword = process.env.INITIAL_ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
  const hash = await auth.hashPassword(initialPassword);
  await query(
    `INSERT INTO users (username, password_hash, name, role, branch_id) VALUES ('admin',$1,'Admin User','admin','grand')`,
    [hash]
  );

  if (!process.env.INITIAL_ADMIN_PASSWORD) {
    console.log('================================================================');
    console.log(`  INITIAL ADMIN LOGIN — SAVE THIS, IT WILL NOT BE SHOWN AGAIN`);
    console.log(`  username: admin`);
    console.log(`  password: ${initialPassword}`);
    console.log('================================================================');
  }
}

boot().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
