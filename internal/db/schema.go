package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const schemaVersion = 2

var migrations = []string{
	// v1: initial schema
	`
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
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
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

CREATE TABLE IF NOT EXISTS schema_version (
  version INTEGER NOT NULL
);

INSERT INTO schema_version (version) VALUES (1);

CREATE INDEX IF NOT EXISTS idx_secrets_vault ON secrets(vault_id);
CREATE INDEX IF NOT EXISTS idx_secrets_state ON secrets(state);
CREATE INDEX IF NOT EXISTS idx_grants_vault ON access_grants(vault_id);
CREATE INDEX IF NOT EXISTS idx_grants_principal ON access_grants(principal_id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_principal ON audit_log(principal_id);
`,
	// v2: add TTL, secret history
	`
ALTER TABLE secrets ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;

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

CREATE INDEX IF NOT EXISTS idx_history_secret ON secret_history(secret_id);

UPDATE schema_version SET version = 2;
`,
}

func Open(path string) (*sql.DB, error) {
	database, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	database.SetConnMaxLifetime(0)

	if err := database.Ping(); err != nil {
		database.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}

	if err := runMigrations(database); err != nil {
		database.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	return database, nil
}

func runMigrations(db *sql.DB) error {
	var currentVersion int
	err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&currentVersion)
	if err != nil {
		currentVersion = 0
	}

	for i := currentVersion; i < len(migrations); i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}
	return nil
}

func WaitForDB(db *sql.DB, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := db.Ping(); err == nil {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("database not ready after %s", timeout)
}

func CleanupExpiredSecrets(db *sql.DB) (int64, error) {
	result, err := db.Exec(
		`UPDATE secrets SET state = 'revoked' WHERE expires_at > 0 AND expires_at < ? AND state = 'active'`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func ArchiveSecretVersion(db *sql.DB, secretID, vaultID, keyName string, ciphertext, nonce []byte, version int, state string, createdAt int64) error {
	_, err := db.Exec(
		`INSERT INTO secret_history (secret_id, vault_id, key_name, ciphertext, nonce, version, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		secretID, vaultID, keyName, ciphertext, nonce, version, state, createdAt,
	)
	return err
}

func CleanupAuditLog(db *sql.DB, retentionDays int) (int64, error) {
	cutoff := time.Now().AddDate(0, 0, -retentionDays).Unix()
	result, err := db.Exec(`DELETE FROM audit_log WHERE timestamp < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func Backup(dbPath, destPath string) error {
	src, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return err
	}
	defer src.Close()

	_, err = src.Exec(fmt.Sprintf(`VACUUM INTO '%s'`, destPath))
	return err
}
