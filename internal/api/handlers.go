package api

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ageis/secrets-manager/internal/auth"
	"github.com/ageis/secrets-manager/internal/crypto"
)

const maxBodySize = 1 << 20

type Server struct {
	db          *sql.DB
	logger      *slog.Logger
	revoker     *auth.TokenRevoker
	corsOrigins []string
}

func New(db *sql.DB, logger *slog.Logger, revoker *auth.TokenRevoker, corsOrigins []string) *Server {
	if corsOrigins == nil {
		corsOrigins = []string{}
	}
	return &Server{db: db, logger: logger, revoker: revoker, corsOrigins: corsOrigins}
}

func (s *Server) Router(authCfg *auth.Config) chi.Router {
	r := chi.NewRouter()

	r.Use(middleware.RealIP)
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/healthz"))
	r.Use(middleware.Timeout(30 * time.Second))
	r.Use(limitBodySize)
	r.Use(securityHeaders)
	r.Use(s.corsMiddleware)
	r.Use(structuredLogger(s.logger))

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(auth.AuthMiddleware(authCfg))

		r.Post("/vaults", s.createVault)
		r.Get("/vaults", s.listVaults)
		r.Delete("/vaults/{vaultID}", s.deleteVault)

		r.Post("/vaults/{vaultID}/secrets", s.createSecret)
		r.Get("/vaults/{vaultID}/secrets", s.listSecrets)
		r.Delete("/vaults/{vaultID}/secrets/{secretID}", s.revokeSecret)
		r.Post("/vaults/{vaultID}/secrets/{secretID}/rotate", s.rotateSecret)

		r.Post("/vaults/{vaultID}/grants", s.grantAccess)
		r.Delete("/vaults/{vaultID}/grants/{principalID}", s.revokeAccess)
		r.Post("/vaults/{vaultID}/rotate-dek", s.rotateDEK)

		r.Post("/decrypt", s.decryptSecret)
		r.Post("/fetch", s.fetchSecretForCI)
		r.Get("/audit", s.getAuditLog)
	})

	return r
}

func (s *Server) audit(principalID, action, resourceType, resourceID, detail string) {
	if _, err := s.db.Exec(
		`INSERT INTO audit_log (principal_id, action, resource_type, resource_id, detail, timestamp) VALUES (?, ?, ?, ?, ?, ?)`,
		principalID, action, resourceType, resourceID, detail, time.Now().Unix(),
	); err != nil {
		s.logger.Error("audit insert failed", "error", err)
	}
}

func (s *Server) hasAccess(principalID, vaultID string) (bool, error) {
	var count int
	if err := s.db.QueryRow(
		`SELECT COUNT(*) FROM access_grants WHERE vault_id = ? AND principal_id = ? AND revoked_at IS NULL`,
		vaultID, principalID,
	).Scan(&count); err != nil {
		return false, err
	}
	return count > 0, nil
}

func (s *Server) mustAccess(w http.ResponseWriter, principalID, vaultID string) bool {
	ok, err := s.hasAccess(principalID, vaultID)
	if err != nil {
		s.logger.Error("hasAccess error", "error", err)
		respondErr(w, 500, "internal error")
		return false
	}
	if !ok {
		respondErr(w, 403, "access denied")
		return false
	}
	return true
}

func limitBodySize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "0")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin != "" && s.isAllowedOrigin(origin) {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) isAllowedOrigin(origin string) bool {
	if len(s.corsOrigins) == 0 {
		return false
	}
	for _, allowed := range s.corsOrigins {
		if allowed == "*" || allowed == origin {
			return true
		}
	}
	return false
}

func structuredLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				logger.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"duration", time.Since(start).String(),
					"remote", r.RemoteAddr,
					"request_id", middleware.GetReqID(r.Context()),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

func respondJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func (s *Server) createVault(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	var req struct {
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	if err := crypto.ValidateVaultName(req.Name); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	pubKey, err := crypto.B64Decode(req.PublicKey)
	if err != nil || len(pubKey) != 32 {
		respondErr(w, 400, "public key must be base64-encoded 32 bytes")
		return
	}

	vaultID, err := crypto.GenerateID()
	if err != nil {
		respondErr(w, 500, "internal error")
		return
	}

	dek := make([]byte, crypto.DEKLen)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		respondErr(w, 500, "internal error")
		return
	}
	defer crypto.ZeroBytes(dek)

	wrapped, err := crypto.WrapDEK(dek, pubKey)
	if err != nil {
		respondErr(w, 500, "failed to wrap DEK")
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		respondErr(w, 500, "internal error")
		return
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`INSERT INTO vaults (id, name, created_at) VALUES (?, ?, ?)`, vaultID, req.Name, time.Now().Unix()); err != nil {
		respondErr(w, 500, "failed to create vault")
		return
	}
	if _, err := tx.Exec(
		`INSERT INTO access_grants (vault_id, principal_id, wrapped_dek, granted_at) VALUES (?, ?, ?, ?)`,
		vaultID, principalID, wrapped, time.Now().Unix(),
	); err != nil {
		respondErr(w, 500, "failed to create grant")
		return
	}
	if _, err := tx.Exec(
		`INSERT INTO principals (id, public_key, encrypted_priv_key) VALUES (?, ?, X'') ON CONFLICT(id) DO UPDATE SET public_key=excluded.public_key`,
		principalID, pubKey,
	); err != nil {
		respondErr(w, 500, "failed to register principal")
		return
	}
	if err := tx.Commit(); err != nil {
		respondErr(w, 500, "commit failed")
		return
	}

	s.audit(principalID, "create_vault", "vault", vaultID, "")
	respondJSON(w, 201, map[string]string{"vault_id": vaultID})
}

func (s *Server) listVaults(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit, err := crypto.ValidateLimit(limitStr, 1, 1000)
	if err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	offset, _ := strconv.Atoi(offsetStr)
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Query(
		`SELECT v.id, v.name, v.created_at
		 FROM vaults v
		 JOIN access_grants g ON g.vault_id = v.id
		 WHERE g.principal_id = ? AND g.revoked_at IS NULL
		 ORDER BY v.created_at DESC LIMIT ? OFFSET ?`, principalID, limit, offset,
	)
	if err != nil {
		respondErr(w, 500, "query failed")
		return
	}
	defer rows.Close()

	type vaultEntry struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CreatedAt int64  `json:"created_at"`
	}
	var out []vaultEntry
	for rows.Next() {
		var v vaultEntry
		if err := rows.Scan(&v.ID, &v.Name, &v.CreatedAt); err != nil {
			s.logger.Error("scan vault", "error", err)
			continue
		}
		out = append(out, v)
	}
	if out == nil {
		out = []vaultEntry{}
	}
	respondJSON(w, 200, out)
}

func (s *Server) deleteVault(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	result, err := s.db.Exec(`DELETE FROM vaults WHERE id = ?`, vaultID)
	if err != nil {
		respondErr(w, 500, "delete failed")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		respondErr(w, 404, "vault not found")
		return
	}

	s.audit(principalID, "delete_vault", "vault", vaultID, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) createSecret(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	var req struct {
		KeyName    string `json:"key_name"`
		Ciphertext string `json:"ciphertext"`
		Nonce      string `json:"nonce"`
		TTL        *int64 `json:"ttl_seconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	if err := crypto.ValidateKeyName(req.KeyName); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	ct, err := crypto.B64Decode(req.Ciphertext)
	if err != nil {
		respondErr(w, 400, "invalid ciphertext")
		return
	}
	nonce, err := crypto.B64Decode(req.Nonce)
	if err != nil {
		respondErr(w, 400, "invalid nonce")
		return
	}

	secretID, err := crypto.GenerateID()
	if err != nil {
		respondErr(w, 500, "internal error")
		return
	}

	var expiresAt int64
	if req.TTL != nil && *req.TTL > 0 {
		expiresAt = time.Now().Unix() + *req.TTL
	}

	_, err = s.db.Exec(
		`INSERT INTO secrets (id, vault_id, key_name, ciphertext, nonce, version, state, created_at, expires_at) VALUES (?, ?, ?, ?, ?, 1, 'active', ?, ?)`,
		secretID, vaultID, req.KeyName, ct, nonce, time.Now().Unix(), expiresAt,
	)
	if err != nil {
		respondErr(w, 500, "db insert failed")
		return
	}

	s.audit(principalID, "create_secret", "secret", secretID, req.KeyName)
	respondJSON(w, 201, map[string]string{"secret_id": secretID})
}

func (s *Server) listSecrets(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	limit, err := crypto.ValidateLimit(limitStr, 1, 1000)
	if err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	offset, _ := strconv.Atoi(offsetStr)
	if offset < 0 {
		offset = 0
	}

	rows, err := s.db.Query(
		`SELECT id, key_name, version, state, created_at, expires_at FROM secrets WHERE vault_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`, vaultID, limit, offset,
	)
	if err != nil {
		respondErr(w, 500, "query failed")
		return
	}
	defer rows.Close()

	type secretSummary struct {
		ID        string `json:"id"`
		KeyName   string `json:"key_name"`
		Version   int    `json:"version"`
		State     string `json:"state"`
		CreatedAt int64  `json:"created_at"`
		ExpiresAt *int64 `json:"expires_at,omitempty"`
	}
	var out []secretSummary
	for rows.Next() {
		var sec secretSummary
		var exp int64
		if err := rows.Scan(&sec.ID, &sec.KeyName, &sec.Version, &sec.State, &sec.CreatedAt, &exp); err != nil {
			s.logger.Error("scan secret", "error", err)
			continue
		}
		if exp > 0 {
			sec.ExpiresAt = &exp
		}
		out = append(out, sec)
	}
	if out == nil {
		out = []secretSummary{}
	}
	respondJSON(w, 200, out)
}

func (s *Server) revokeSecret(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")
	secretID := chi.URLParam(r, "secretID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	result, err := s.db.Exec(
		`UPDATE secrets SET state = 'revoked' WHERE id = ? AND vault_id = ? AND state = 'active'`,
		secretID, vaultID,
	)
	if err != nil {
		respondErr(w, 500, "update failed")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		respondErr(w, 404, "secret not found or already revoked")
		return
	}

	s.audit(principalID, "revoke_secret", "secret", secretID, "")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateSecret(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")
	secretID := chi.URLParam(r, "secretID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	var req struct {
		NewCiphertext string `json:"new_ciphertext"`
		NewNonce      string `json:"new_nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	newCT, err := crypto.B64Decode(req.NewCiphertext)
	if err != nil {
		respondErr(w, 400, "invalid new ciphertext")
		return
	}
	newNonce, err := crypto.B64Decode(req.NewNonce)
	if err != nil {
		respondErr(w, 400, "invalid new nonce")
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		respondErr(w, 500, "internal error")
		return
	}
	defer tx.Rollback()

	var currentVersion int
	var currentState, keyName string
	var oldCT, oldNonce []byte
	var createdAt int64
	err = tx.QueryRow(
		`SELECT version, state, key_name, ciphertext, nonce, created_at FROM secrets WHERE id = ? AND vault_id = ?`, secretID, vaultID,
	).Scan(&currentVersion, &currentState, &keyName, &oldCT, &oldNonce, &createdAt)
	if err == sql.ErrNoRows {
		respondErr(w, 404, "secret not found")
		return
	}
	if err != nil {
		respondErr(w, 500, "db error")
		return
	}
	if currentState == "revoked" {
		respondErr(w, 410, "secret is revoked")
		return
	}
	if currentState == "rotated" {
		respondErr(w, 409, "secret already rotated, fetch current version first")
		return
	}

	if err := ArchiveSecretVersion(tx, secretID, vaultID, keyName, oldCT, oldNonce, currentVersion, currentState, createdAt); err != nil {
		s.logger.Error("archive secret version", "error", err)
	}

	newVersion := currentVersion + 1
	_, err = tx.Exec(
		`UPDATE secrets SET state = 'active', ciphertext = ?, nonce = ?, version = ? WHERE id = ?`,
		newCT, newNonce, newVersion, secretID,
	)
	if err != nil {
		respondErr(w, 500, "rotate failed")
		return
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, 500, "commit failed")
		return
	}

	s.audit(principalID, "rotate_secret", "secret", secretID, fmt.Sprintf("v%d->v%d", currentVersion, newVersion))
	respondJSON(w, 200, map[string]interface{}{
		"status":  "rotated",
		"version": newVersion,
	})
}

func ArchiveSecretVersion(tx *sql.Tx, secretID, vaultID, keyName string, ciphertext, nonce []byte, version int, state string, createdAt int64) error {
	_, err := tx.Exec(
		`INSERT INTO secret_history (secret_id, vault_id, key_name, ciphertext, nonce, version, state, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		secretID, vaultID, keyName, ciphertext, nonce, version, state, createdAt,
	)
	return err
}

func (s *Server) rotateDEK(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	var req struct {
		NewWrappedDEKs []struct {
			PrincipalID string `json:"principal_id"`
			WrappedDEK  string `json:"wrapped_dek"`
		} `json:"new_wrapped_deks"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	if len(req.NewWrappedDEKs) == 0 {
		respondErr(w, 400, "new_wrapped_deks required")
		return
	}

	tx, err := s.db.Begin()
	if err != nil {
		respondErr(w, 500, "internal error")
		return
	}
	defer tx.Rollback()

	for _, grant := range req.NewWrappedDEKs {
		wrapped, err := crypto.B64Decode(grant.WrappedDEK)
		if err != nil {
			respondErr(w, 400, "invalid wrapped_dek")
			return
		}
		if _, err := tx.Exec(
			`UPDATE access_grants SET wrapped_dek = ?, granted_at = ? WHERE vault_id = ? AND principal_id = ? AND revoked_at IS NULL`,
			wrapped, time.Now().Unix(), vaultID, grant.PrincipalID,
		); err != nil {
			respondErr(w, 500, "update grant failed")
			return
		}
	}

	if err := tx.Commit(); err != nil {
		respondErr(w, 500, "commit failed")
		return
	}

	s.audit(principalID, "rotate_dek", "vault", vaultID, fmt.Sprintf("%d grants updated", len(req.NewWrappedDEKs)))
	respondJSON(w, 200, map[string]string{"status": "dek rotated"})
}

func (s *Server) decryptSecret(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	var req struct {
		SecretID string `json:"secret_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	if req.SecretID == "" {
		respondErr(w, 400, "secret_id required")
		return
	}

	var ct, nonce []byte
	var vaultID, state string
	err := s.db.QueryRow(
		`SELECT ciphertext, nonce, vault_id, state FROM secrets WHERE id = ?`, req.SecretID,
	).Scan(&ct, &nonce, &vaultID, &state)
	if err == sql.ErrNoRows {
		respondErr(w, 404, "secret not found")
		return
	}
	if err != nil {
		respondErr(w, 500, "internal error")
		return
	}
	if state != "active" {
		respondErr(w, 410, "secret is "+state)
		return
	}

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	var wrappedDEK []byte
	err = s.db.QueryRow(
		`SELECT wrapped_dek FROM access_grants WHERE vault_id = ? AND principal_id = ? AND revoked_at IS NULL`,
		vaultID, principalID,
	).Scan(&wrappedDEK)
	if err != nil {
		respondErr(w, 403, "no grant for this principal")
		return
	}

	s.audit(principalID, "decrypt", "secret", req.SecretID, "")
	respondJSON(w, 200, map[string]string{
		"ciphertext":  crypto.B64Encode(ct),
		"nonce":       crypto.B64Encode(nonce),
		"wrapped_dek": crypto.B64Encode(wrappedDEK),
	})
}

func (s *Server) grantAccess(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}

	var req struct {
		NewPrincipalID string `json:"principal_id"`
		WrappedDEK     string `json:"wrapped_dek"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	if err := crypto.ValidatePrincipalID(req.NewPrincipalID); err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	wrapped, err := crypto.B64Decode(req.WrappedDEK)
	if err != nil {
		respondErr(w, 400, "invalid wrapped_dek")
		return
	}

	if _, err := s.db.Exec(
		`INSERT INTO access_grants (vault_id, principal_id, wrapped_dek, granted_at) VALUES (?, ?, ?, ?)
		 ON CONFLICT(vault_id, principal_id) DO UPDATE SET wrapped_dek=excluded.wrapped_dek, granted_at=excluded.granted_at, revoked_at=NULL`,
		vaultID, req.NewPrincipalID, wrapped, time.Now().Unix(),
	); err != nil {
		respondErr(w, 500, "grant failed")
		return
	}

	s.audit(principalID, "grant", "vault", vaultID, "granted to "+req.NewPrincipalID)
	respondJSON(w, 201, map[string]string{"status": "granted"})
}

func (s *Server) revokeAccess(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	vaultID := chi.URLParam(r, "vaultID")
	targetPrincipal := chi.URLParam(r, "principalID")

	if !s.mustAccess(w, principalID, vaultID) {
		return
	}
	if principalID == targetPrincipal {
		respondErr(w, 400, "cannot revoke own access")
		return
	}

	result, err := s.db.Exec(
		`UPDATE access_grants SET revoked_at = ? WHERE vault_id = ? AND principal_id = ? AND revoked_at IS NULL`,
		time.Now().Unix(), vaultID, targetPrincipal,
	)
	if err != nil {
		respondErr(w, 500, "revoke failed")
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		respondErr(w, 404, "grant not found")
		return
	}

	s.audit(principalID, "revoke", "vault", vaultID, "revoked "+targetPrincipal)
	respondJSON(w, 200, map[string]string{"status": "revoked"})
}

func (s *Server) fetchSecretForCI(w http.ResponseWriter, r *http.Request) {
	principalID := auth.PrincipalFromContext(r.Context())
	var req struct {
		SecretID string `json:"secret_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondErr(w, 400, "invalid JSON body")
		return
	}
	if req.SecretID == "" {
		respondErr(w, 400, "secret_id required")
		return
	}

	var keyName, state string
	var ct, nonce, wrappedDEK []byte
	err := s.db.QueryRow(
		`SELECT s.key_name, s.ciphertext, s.nonce, s.state, g.wrapped_dek
		 FROM secrets s
		 JOIN access_grants g ON g.vault_id = s.vault_id AND g.revoked_at IS NULL
		 WHERE s.id = ? AND g.principal_id = ?`,
		req.SecretID, principalID,
	).Scan(&keyName, &ct, &nonce, &state, &wrappedDEK)
	if err != nil {
		respondErr(w, 403, "not found or access denied")
		return
	}
	if state != "active" {
		respondErr(w, 410, "secret is "+state)
		return
	}

	s.audit(principalID, "fetch", "secret", req.SecretID, keyName)
	respondJSON(w, 200, map[string]string{
		"key_name":    keyName,
		"ciphertext":  crypto.B64Encode(ct),
		"nonce":       crypto.B64Encode(nonce),
		"wrapped_dek": crypto.B64Encode(wrappedDEK),
	})
}

func (s *Server) getAuditLog(w http.ResponseWriter, r *http.Request) {
	limitStr := r.URL.Query().Get("limit")
	offsetStr := r.URL.Query().Get("offset")
	filterPrincipal := r.URL.Query().Get("principal_id")
	filterAction := r.URL.Query().Get("action")

	limit, err := crypto.ValidateLimit(limitStr, 1, 1000)
	if err != nil {
		respondErr(w, 400, err.Error())
		return
	}
	offset, _ := strconv.Atoi(offsetStr)
	if offset < 0 {
		offset = 0
	}

	query := `SELECT id, principal_id, action, resource_type, resource_id, detail, timestamp FROM audit_log WHERE 1=1`
	var args []interface{}

	if filterPrincipal != "" {
		query += ` AND principal_id = ?`
		args = append(args, filterPrincipal)
	}
	if filterAction != "" {
		query += ` AND action = ?`
		args = append(args, filterAction)
	}
	query += ` ORDER BY timestamp DESC LIMIT ? OFFSET ?`
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		respondErr(w, 500, "query failed")
		return
	}
	defer rows.Close()

	type auditEntry struct {
		ID           int64  `json:"id"`
		PrincipalID  string `json:"principal_id"`
		Action       string `json:"action"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Detail       string `json:"detail"`
		Timestamp    int64  `json:"timestamp"`
	}
	var out []auditEntry
	for rows.Next() {
		var e auditEntry
		if err := rows.Scan(&e.ID, &e.PrincipalID, &e.Action, &e.ResourceType, &e.ResourceID, &e.Detail, &e.Timestamp); err != nil {
			s.logger.Error("scan audit", "error", err)
			continue
		}
		out = append(out, e)
	}
	if out == nil {
		out = []auditEntry{}
	}
	respondJSON(w, 200, out)
}

func (s *Server) CreateHTTPServer(addr string, tlsCfg *tls.Config, authCfg *auth.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Router(authCfg),
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func (s *Server) Run(addr string, tlsCfg *tls.Config, authCfg *auth.Config) error {
	s.logger.Info("daemon starting", "addr", addr)
	srv := s.CreateHTTPServer(addr, tlsCfg, authCfg)
	if tlsCfg != nil {
		return srv.ListenAndServeTLS("", "")
	}
	return srv.ListenAndServe()
}

func (s *Server) IsSecretExpired(expiresAt int64) bool {
	return expiresAt > 0 && time.Now().Unix() > expiresAt
}
