-- Zero-Knowledge Secrets Manager — SQLite Schema
-- WAL journal mode, enforced via connection string pragma

-- Schema version tracking
CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);
INSERT OR IGNORE INTO schema_version (version) VALUES (2);

CREATE TABLE IF NOT EXISTS vaults (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS secrets (
  id TEXT PRIMARY KEY,
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  key_name TEXT NOT NULL CHECK(length(key_name) > 0 AND length(key_name) <= 256),
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL CHECK(state IN ('active','rotation_pending','rotated','revoked')),
  created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  expires_at INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS principals (
  id TEXT PRIMARY KEY,
  public_key BLOB NOT NULL,
  encrypted_priv_key BLOB NOT NULL DEFAULT (X'')
);

CREATE TABLE IF NOT EXISTS access_grants (
  vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
  wrapped_dek BLOB NOT NULL,
  granted_at INTEGER NOT NULL DEFAULT (unixepoch()),
  revoked_at INTEGER,
  PRIMARY KEY (vault_id, principal_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  principal_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL DEFAULT '',
  resource_id TEXT NOT NULL DEFAULT '',
  detail TEXT NOT NULL DEFAULT '',
  timestamp INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS secret_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  secret_id TEXT NOT NULL,
  vault_id TEXT NOT NULL,
  key_name TEXT NOT NULL,
  ciphertext BLOB NOT NULL,
  nonce BLOB NOT NULL,
  version INTEGER NOT NULL,
  state TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  archived_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE INDEX IF NOT EXISTS idx_secrets_vault ON secrets(vault_id);
CREATE INDEX IF NOT EXISTS idx_secrets_state ON secrets(state);
CREATE INDEX IF NOT EXISTS idx_secrets_expires ON secrets(expires_at);
CREATE INDEX IF NOT EXISTS idx_grants_vault ON access_grants(vault_id);
CREATE INDEX IF NOT EXISTS idx_grants_principal ON access_grants(principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal_id);
CREATE INDEX IF NOT EXISTS idx_history_secret ON secret_history(secret_id);
