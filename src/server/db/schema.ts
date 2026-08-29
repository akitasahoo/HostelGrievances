import type { Database } from 'better-sqlite3';

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('student', 'warden')),
  room TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS user_mfa (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  totp_secret TEXT,
  mfa_level INTEGER NOT NULL DEFAULT 1,
  hardware_pin_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS grievances (
  id TEXT PRIMARY KEY,
  student_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'in_progress', 'resolved')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  grievance_id TEXT NOT NULL REFERENCES grievances(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id),
  body TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY,
  grievance_id TEXT NOT NULL REFERENCES grievances(id) ON DELETE CASCADE,
  original_filename TEXT NOT NULL,
  stored_filename TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor_id TEXT,
  actor_email TEXT,
  action TEXT NOT NULL,
  resource TEXT,
  outcome TEXT NOT NULL,
  ip TEXT,
  details TEXT,
  prev_hash TEXT,
  entry_hash TEXT
);

CREATE TABLE IF NOT EXISTS threat_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  ip TEXT,
  user_id TEXT,
  risk_score INTEGER NOT NULL,
  anomaly_factors TEXT,
  payload_threat INTEGER DEFAULT 0,
  mfa_level INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_grievances_student ON grievances(student_id);
CREATE INDEX IF NOT EXISTS idx_comments_grievance ON comments(grievance_id);
CREATE INDEX IF NOT EXISTS idx_attachments_grievance ON attachments(grievance_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit_events(at);
CREATE INDEX IF NOT EXISTS idx_threat_logs_at ON threat_logs(at);
`;

export function applySchema(db: Database): void {
	db.exec('PRAGMA foreign_keys = ON;');
	db.exec(SCHEMA_SQL);

	// Ensure columns exist on existing DB tables if migrations run
	try {
		const auditCols = db.prepare('PRAGMA table_info(audit_events)').all() as { name: string }[];
		const colNames = auditCols.map((c) => c.name);
		if (!colNames.includes('prev_hash')) {
			db.exec('ALTER TABLE audit_events ADD COLUMN prev_hash TEXT;');
		}
		if (!colNames.includes('entry_hash')) {
			db.exec('ALTER TABLE audit_events ADD COLUMN entry_hash TEXT;');
		}
	} catch (_) {
		// Ignore if already present
	}
}
