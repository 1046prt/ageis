package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ageis/secrets-manager/internal/auth"
	"github.com/ageis/secrets-manager/internal/crypto"
	"github.com/ageis/secrets-manager/internal/db"
)

const testPrincipal = "test-user"

func setupTestDB(t *testing.T) *Server {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	revoker := auth.NewTokenRevoker(1 * time.Hour)
	return New(database, logger, revoker, nil)
}

func withAuthConfig() *auth.Config {
	return &auth.Config{JWTSecret: []byte("test-secret-key-32bytes-long!!!")}
}

func doRequest(t *testing.T, r chi.Router, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		data, _ := json.Marshal(body)
		reqBody = bytes.NewReader(data)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.WithPrincipal(req.Context(), testPrincipal))

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestCreateVault(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test-vault",
	})
	if rr.Code != 201 {
		t.Fatalf("create vault: status %d, body %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["vault_id"] == "" {
		t.Fatal("vault_id is empty")
	}
}

func TestListVaults(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "my-vault",
	})
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}

	rr = doRequest(t, r, "GET", "/api/v1/vaults", nil)
	if rr.Code != 200 {
		t.Fatalf("list vaults: status %d", rr.Code)
	}

	var vaults []map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &vaults)
	if len(vaults) != 1 {
		t.Fatalf("expected 1 vault, got %d", len(vaults))
	}
}

func TestCreateSecret(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})
	var vaultResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &vaultResp)
	vaultID := vaultResp["vault_id"]

	dek := make([]byte, crypto.DEKLen)
	ct, nonce, _ := crypto.EncryptGCM(dek, []byte("my-password"), nil)

	rr = doRequest(t, r, "POST", fmt.Sprintf("/api/v1/vaults/%s/secrets", vaultID), map[string]string{
		"key_name":   "DB_PASSWORD",
		"ciphertext": crypto.B64Encode(ct),
		"nonce":      crypto.B64Encode(nonce),
	})
	if rr.Code != 201 {
		t.Fatalf("create secret: status %d, body %s", rr.Code, rr.Body.String())
	}
}

func TestFetchSecretEndToEnd(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})
	var vaultResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &vaultResp)
	vaultID := vaultResp["vault_id"]

	dek := make([]byte, crypto.DEKLen)
	plaintext := []byte("hunter2-password")
	ct, nonce, _ := crypto.EncryptGCM(dek, plaintext, nil)

	rr = doRequest(t, r, "POST", fmt.Sprintf("/api/v1/vaults/%s/secrets", vaultID), map[string]string{
		"key_name":   "DB_PASSWORD",
		"ciphertext": crypto.B64Encode(ct),
		"nonce":      crypto.B64Encode(nonce),
	})
	if rr.Code != 201 {
		t.Fatal(rr.Body.String())
	}
	var secResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &secResp)

	rr = doRequest(t, r, "POST", "/api/v1/fetch", map[string]string{
		"secret_id": secResp["secret_id"],
	})
	if rr.Code != 200 {
		t.Fatalf("fetch: status %d, body %s", rr.Code, rr.Body.String())
	}

	var fetchResp struct {
		KeyName    string `json:"key_name"`
		Ciphertext string `json:"ciphertext"`
		Nonce      string `json:"nonce"`
		WrappedDEK string `json:"wrapped_dek"`
	}
	json.Unmarshal(rr.Body.Bytes(), &fetchResp)

	wrappedDEK, _ := crypto.B64Decode(fetchResp.WrappedDEK)
	gotDEK, err := crypto.UnwrapDEK(wrappedDEK, kp.PrivateKey[:])
	if err != nil {
		t.Fatalf("unwrap DEK: %v", err)
	}
	ctBytes, _ := crypto.B64Decode(fetchResp.Ciphertext)
	nonceBytes, _ := crypto.B64Decode(fetchResp.Nonce)
	gotPlain, err := crypto.DecryptGCM(gotDEK, ctBytes, nonceBytes, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(gotPlain, plaintext) {
		t.Fatalf("decrypted: got %q, want %q", gotPlain, plaintext)
	}
}

func TestRevokeSecret(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})
	var vaultResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &vaultResp)
	vaultID := vaultResp["vault_id"]

	dek := make([]byte, crypto.DEKLen)
	ct, nonce, _ := crypto.EncryptGCM(dek, []byte("data"), nil)

	rr = doRequest(t, r, "POST", fmt.Sprintf("/api/v1/vaults/%s/secrets", vaultID), map[string]string{
		"key_name":   "TEST",
		"ciphertext": crypto.B64Encode(ct),
		"nonce":      crypto.B64Encode(nonce),
	})
	var secResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &secResp)

	rr = doRequest(t, r, "DELETE", fmt.Sprintf("/api/v1/vaults/%s/secrets/%s", vaultID, secResp["secret_id"]), nil)
	if rr.Code != 204 {
		t.Fatalf("revoke: status %d, body %s", rr.Code, rr.Body.String())
	}
}

func TestUnauthorized(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	req := httptest.NewRequest("GET", "/api/v1/vaults", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != 401 {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestGrantAndRevokeAccess(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})
	var vaultResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &vaultResp)
	vaultID := vaultResp["vault_id"]

	otherKP, _ := crypto.GenerateX25519KeyPair()
	wrapped, _ := crypto.WrapDEK(make([]byte, crypto.DEKLen), otherKP.PublicKey[:])

	rr = doRequest(t, r, "POST", fmt.Sprintf("/api/v1/vaults/%s/grants", vaultID), map[string]string{
		"principal_id": "ci-runner-2",
		"wrapped_dek":  crypto.B64Encode(wrapped),
	})
	if rr.Code != 201 {
		t.Fatalf("grant: status %d, body %s", rr.Code, rr.Body.String())
	}

	rr = doRequest(t, r, "DELETE", fmt.Sprintf("/api/v1/vaults/%s/grants/ci-runner-2", vaultID), nil)
	if rr.Code != 200 {
		t.Fatalf("revoke: status %d, body %s", rr.Code, rr.Body.String())
	}
}

func TestRevokeOwnAccessBlocked(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})
	var vaultResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &vaultResp)
	vaultID := vaultResp["vault_id"]

	rr = doRequest(t, r, "DELETE", fmt.Sprintf("/api/v1/vaults/%s/grants/test-user", vaultID), nil)
	if rr.Code != 400 {
		t.Fatalf("expected 400 for self-revoke, got %d, body %s", rr.Code, rr.Body.String())
	}
}

func TestDecryptRevokedSecret(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	rr := doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})
	var vaultResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &vaultResp)
	vaultID := vaultResp["vault_id"]

	dek := make([]byte, crypto.DEKLen)
	ct, nonce, _ := crypto.EncryptGCM(dek, []byte("data"), nil)

	rr = doRequest(t, r, "POST", fmt.Sprintf("/api/v1/vaults/%s/secrets", vaultID), map[string]string{
		"key_name":   "TEST",
		"ciphertext": crypto.B64Encode(ct),
		"nonce":      crypto.B64Encode(nonce),
	})
	var secResp map[string]string
	json.Unmarshal(rr.Body.Bytes(), &secResp)

	doRequest(t, r, "DELETE", fmt.Sprintf("/api/v1/vaults/%s/secrets/%s", vaultID, secResp["secret_id"]), nil)

	rr = doRequest(t, r, "POST", "/api/v1/decrypt", map[string]string{
		"secret_id": secResp["secret_id"],
	})
	if rr.Code != 410 {
		t.Fatalf("expected 410 for revoked secret, got %d, body %s", rr.Code, rr.Body.String())
	}
}

func TestAuditLogFiltering(t *testing.T) {
	s := setupTestDB(t)
	r := s.Router(withAuthConfig())

	kp, _ := crypto.GenerateX25519KeyPair()
	pubB64 := crypto.B64Encode(kp.PublicKey[:])

	doRequest(t, r, "POST", "/api/v1/vaults", map[string]string{
		"public_key": pubB64,
		"name":       "test",
	})

	rr := doRequest(t, r, "GET", "/api/v1/audit?limit=10&action=create_vault", nil)
	if rr.Code != 200 {
		t.Fatalf("audit filter: status %d", rr.Code)
	}

	var entries []map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &entries)
	for _, e := range entries {
		if e["action"] != "create_vault" {
			t.Fatalf("expected action=create_vault, got %v", e["action"])
		}
	}
}
