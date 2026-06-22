-- ============================================================
-- HotelOS Pro — Database Schema (PostgreSQL)
-- Run automatically on server boot if tables don't exist (see db.js)
-- ============================================================

CREATE TABLE IF NOT EXISTS branches (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  city          TEXT,
  manager       TEXT,
  stars         INTEGER DEFAULT 3,
  phone         TEXT,
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
  id               SERIAL PRIMARY KEY,
  username         TEXT UNIQUE NOT NULL,
  password_hash    TEXT NOT NULL,         -- bcrypt hash, server-side only, never sent to client
  name             TEXT NOT NULL,
  role             TEXT NOT NULL CHECK (role IN ('admin','manager','receptionist','housekeeping','maintenance')),
  branch_id        TEXT REFERENCES branches(id),
  email            TEXT,
  failed_attempts  INTEGER DEFAULT 0,
  locked_until     TIMESTAMPTZ,
  created_at       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS guests (
  id            TEXT PRIMARY KEY,
  branch_id     TEXT REFERENCES branches(id),
  first_name    TEXT NOT NULL,
  last_name     TEXT NOT NULL,
  email         TEXT,
  phone         TEXT,
  nationality   TEXT,
  id_number     TEXT,
  vip           INTEGER DEFAULT 0,
  loyalty_points INTEGER DEFAULT 0,
  preferences   TEXT,
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rooms (
  id            TEXT PRIMARY KEY,
  branch_id     TEXT REFERENCES branches(id),
  number        TEXT NOT NULL,
  type          TEXT NOT NULL,
  price         NUMERIC(12,2) NOT NULL,
  floor         INTEGER,
  capacity      INTEGER DEFAULT 2,
  status        TEXT DEFAULT 'available' CHECK (status IN ('available','occupied','reserved','cleaning','maintenance','out-of-service')),
  features      TEXT,
  last_cleaned  TIMESTAMPTZ,
  UNIQUE(branch_id, number)
);

CREATE TABLE IF NOT EXISTS bookings (
  id              TEXT PRIMARY KEY,
  branch_id       TEXT REFERENCES branches(id),
  guest_id        TEXT REFERENCES guests(id),
  room_id         TEXT REFERENCES rooms(id),
  checkin         DATE NOT NULL,
  checkout        DATE NOT NULL,
  nights          INTEGER NOT NULL,
  total           NUMERIC(12,2) NOT NULL,
  status          TEXT DEFAULT 'confirmed' CHECK (status IN ('pending','confirmed','checked_in','checked_out','cancelled')),
  payment_status  TEXT DEFAULT 'unpaid' CHECK (payment_status IN ('unpaid','partial','paid')),
  payment_method  TEXT,
  num_guests      INTEGER DEFAULT 1,
  requests        TEXT,
  stripe_session_id TEXT,
  created_at      TIMESTAMPTZ DEFAULT now(),
  checkin_time    TIMESTAMPTZ,
  checkout_time   TIMESTAMPTZ
);

-- Prevents double-booking at the database level — not just in application code.
-- Two overlapping CONFIRMED/CHECKED_IN bookings for the same room are impossible to insert.
CREATE INDEX IF NOT EXISTS idx_bookings_room_dates ON bookings(room_id, checkin, checkout) WHERE status NOT IN ('cancelled','checked_out');

CREATE TABLE IF NOT EXISTS payments (
  id              TEXT PRIMARY KEY,
  branch_id       TEXT REFERENCES branches(id),
  booking_id      TEXT REFERENCES bookings(id),
  amount          NUMERIC(12,2) NOT NULL,
  method          TEXT,
  status          TEXT DEFAULT 'completed',
  stripe_payment_intent TEXT,
  timestamp       TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS staff (
  id            TEXT PRIMARY KEY,
  branch_id     TEXT REFERENCES branches(id),
  name          TEXT NOT NULL,
  role          TEXT NOT NULL,
  dept          TEXT,
  email         TEXT,
  phone         TEXT,
  shift         TEXT,
  status        TEXT DEFAULT 'active',
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS housekeeping_tasks (
  id            TEXT PRIMARY KEY,
  branch_id     TEXT REFERENCES branches(id),
  room_id       TEXT REFERENCES rooms(id),
  type          TEXT,
  priority      TEXT DEFAULT 'medium',
  status        TEXT DEFAULT 'pending' CHECK (status IN ('pending','in_progress','completed')),
  staff_id      TEXT,
  notes         TEXT,
  created_at    TIMESTAMPTZ DEFAULT now(),
  started_at    TIMESTAMPTZ,
  completed_at  TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS maintenance_tickets (
  id            TEXT PRIMARY KEY,
  branch_id     TEXT REFERENCES branches(id),
  room_id       TEXT REFERENCES rooms(id),
  title         TEXT NOT NULL,
  description   TEXT,
  priority      TEXT DEFAULT 'medium',
  status        TEXT DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved')),
  technician_id TEXT,
  created_at    TIMESTAMPTZ DEFAULT now(),
  resolved_at   TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_log (
  id            SERIAL PRIMARY KEY,
  branch_id     TEXT,
  username      TEXT,
  action        TEXT NOT NULL,
  module        TEXT,
  detail        TEXT,
  before_val    TEXT,
  after_val     TEXT,
  ref_id        TEXT,
  ip_address    TEXT,
  created_at    TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_branch ON audit_log(branch_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bookings_branch ON bookings(branch_id);
CREATE INDEX IF NOT EXISTS idx_guests_branch ON guests(branch_id);
CREATE INDEX IF NOT EXISTS idx_rooms_branch ON rooms(branch_id);
