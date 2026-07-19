package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const PrincipalKey contextKey = "principal"

type Config struct {
	JWTSecret   []byte
	AllowedCAs  *x509.CertPool
	RequireMTLS bool
}

type Claims struct {
	PrincipalID string   `json:"sub"`
	JTI         string   `json:"jti"`
	VaultAccess []string `json:"vaults,omitempty"`
	jwt.RegisteredClaims
}

type TokenRevoker struct {
	mu       sync.RWMutex
	revoked  map[string]time.Time
	ttl      time.Duration
	stopChan chan struct{}
}

func NewTokenRevoker(ttl time.Duration) *TokenRevoker {
	tr := &TokenRevoker{
		revoked:  make(map[string]time.Time),
		ttl:      ttl,
		stopChan: make(chan struct{}),
	}
	go tr.cleanup()
	return tr
}

func (tr *TokenRevoker) Revoke(jti string) {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	tr.revoked[jti] = time.Now().Add(tr.ttl)
}

func (tr *TokenRevoker) IsRevoked(jti string) bool {
	tr.mu.RLock()
	defer tr.mu.RUnlock()
	expiry, ok := tr.revoked[jti]
	if !ok {
		return false
	}
	if time.Now().After(expiry) {
		return false
	}
	return true
}

func (tr *TokenRevoker) Stop() {
	close(tr.stopChan)
}

func (tr *TokenRevoker) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			tr.mu.Lock()
			now := time.Now()
			for jti, expiry := range tr.revoked {
				if now.After(expiry) {
					delete(tr.revoked, jti)
				}
			}
			tr.mu.Unlock()
		case <-tr.stopChan:
			return
		}
	}
}

func PrincipalFromContext(ctx context.Context) string {
	if p, ok := ctx.Value(PrincipalKey).(string); ok {
		return p
	}
	return ""
}

func WithPrincipal(ctx context.Context, principalID string) context.Context {
	return context.WithValue(ctx, PrincipalKey, principalID)
}

func AuthMiddleware(cfg *Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, err := extractPrincipal(r, cfg)
			if err != nil {
				respondAuthErr(w)
				return
			}
			ctx := context.WithValue(r.Context(), PrincipalKey, principal)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func respondAuthErr(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
}

func extractPrincipal(r *http.Request, cfg *Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("no auth configured")
	}
	if cfg.RequireMTLS {
		if p, err := extractFromMTLS(r, cfg); err == nil {
			return p, nil
		}
	}
	if len(cfg.JWTSecret) > 0 {
		if p, err := extractFromJWT(r, cfg); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("no valid authentication")
}

func extractFromMTLS(r *http.Request, cfg *Config) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no client certificate")
	}
	cert := r.TLS.PeerCertificates[0]

	if cfg.AllowedCAs != nil {
		opts := x509.VerifyOptions{
			Roots:     cfg.AllowedCAs,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		if _, err := cert.Verify(opts); err != nil {
			return "", fmt.Errorf("certificate verification failed")
		}
	}

	if cert.Subject.CommonName == "" {
		return "", fmt.Errorf("certificate has no CN")
	}
	return cert.Subject.CommonName, nil
}

func extractFromJWT(r *http.Request, cfg *Config) (string, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return "", fmt.Errorf("no Authorization header")
	}
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
		return "", fmt.Errorf("invalid Authorization format")
	}

	token, err := jwt.ParseWithClaims(parts[1], &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return cfg.JWTSecret, nil
	})
	if err != nil {
		return "", fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token claims")
	}
	if claims.ExpiresAt != nil && claims.ExpiresAt.Time.Before(time.Now()) {
		return "", fmt.Errorf("token expired")
	}
	if claims.PrincipalID == "" {
		return "", fmt.Errorf("token missing subject")
	}
	return claims.PrincipalID, nil
}

func GenerateJWT(secret []byte, principalID string, ttl time.Duration) (string, error) {
	jti := make([]byte, 16)
	if _, err := rand.Read(jti); err != nil {
		return "", fmt.Errorf("generate JTI: %w", err)
	}

	claims := &Claims{
		PrincipalID: principalID,
		JTI:         fmt.Sprintf("%x", jti),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   principalID,
			ID:        fmt.Sprintf("%x", jti),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}

func LoadTLSConfig(certPath, keyPath, caPath string, requireClientCert bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("load server cert: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if requireClientCert && caPath != "" {
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.ClientCAs = pool
		tlsCfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return tlsCfg, nil
}

func WriteJWTToFile(path string, secret []byte, principalID string, ttl time.Duration) error {
	token, err := GenerateJWT(secret, principalID, ttl)
	if err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]string{"token": token})
	return os.WriteFile(path, data, 0600)
}
