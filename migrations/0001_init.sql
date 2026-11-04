CREATE TABLE IF NOT EXISTS tries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  saved_at TEXT NOT NULL,
  visitor TEXT NOT NULL,
  page_version TEXT NOT NULL,
  consent_v INTEGER NOT NULL,
  mode TEXT NOT NULL,
  card TEXT NOT NULL,
  sentence TEXT NOT NULL,
  verdict TEXT NOT NULL,
  codes TEXT NOT NULL,
  checked TEXT NOT NULL,
  answer TEXT,
  beat_checker INTEGER,
  note TEXT,
  redacted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS visitors (
  code TEXT PRIMARY KEY,
  delete_hash TEXT,
  first_seen TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS tries_visitor_idx ON tries(visitor);
CREATE INDEX IF NOT EXISTS tries_saved_at_idx ON tries(saved_at);
