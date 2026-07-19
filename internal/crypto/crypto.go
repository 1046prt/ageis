package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/curve25519"
)

const (
	DEKLen          = 32
	NonceLen        = 12
	SaltLen         = 16
	WrapFormatVer   = 1
	WrapFixedPrefix = 1 // 1 byte version
)

var (
	ErrDecryptFailed = errors.New("decryption failed: wrong key or corrupted data")
	ErrInvalidKey    = errors.New("invalid key material")
	ErrKeyTooShort   = errors.New("key material too short")
	ErrFormatVersion = errors.New("unsupported wrap format version")
)

type Argon2Params struct {
	MemoryKB uint32
	Ops      uint32
	Threads  uint8
}

var DefaultArgon2 = Argon2Params{MemoryKB: 256 * 1024, Ops: 4, Threads: 4}

func DeriveMasterKey(password string, salt []byte, params Argon2Params) []byte {
	return argon2.IDKey([]byte(password), salt, params.Ops, params.MemoryKB, uint32(params.Threads), DEKLen)
}

func NewSalt() ([]byte, error) {
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	return salt, nil
}

func GenerateID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("generate ID: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func EncryptGCM(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("aes.NewCipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewGCM: %w", err)
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

func DecryptGCM(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	return plaintext, nil
}

type X25519KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	var priv [32]byte
	if _, err := io.ReadFull(rand.Reader, priv[:]); err != nil {
		return nil, fmt.Errorf("generate X25519 key: %w", err)
	}
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("X25519 scalar base: %w", err)
	}
	var pubArr [32]byte
	copy(pubArr[:], pub)
	return &X25519KeyPair{PrivateKey: priv, PublicKey: pubArr}, nil
}

func SharedSecret(privKey, pubKey []byte) ([]byte, error) {
	shared, err := curve25519.X25519(privKey, pubKey)
	if err != nil {
		return nil, fmt.Errorf("X25519 ECDH: %w", err)
	}
	hash := sha256.Sum256(shared)
	ZeroBytes(shared)
	return hash[:], nil
}

func WrapDEK(dek, recipientPubKey []byte) ([]byte, error) {
	if len(dek) != DEKLen {
		return nil, ErrKeyTooShort
	}
	ephemeral, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(ephemeral.PrivateKey[:])

	symKey, err := SharedSecret(ephemeral.PrivateKey[:], recipientPubKey)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(symKey)

	ct, nonce, err := EncryptGCM(symKey, dek, nil)
	if err != nil {
		return nil, err
	}

	result := make([]byte, 0, WrapFixedPrefix+32+NonceLen+len(ct))
	result = append(result, byte(WrapFormatVer))
	result = append(result, ephemeral.PublicKey[:]...)
	result = append(result, nonce...)
	result = append(result, ct...)
	return result, nil
}

func UnwrapDEK(wrappedDEK, recipientPrivKey []byte) ([]byte, error) {
	if len(wrappedDEK) < WrapFixedPrefix+32+NonceLen+1 {
		return nil, ErrInvalidKey
	}

	ver := wrappedDEK[0]
	if ver != WrapFormatVer {
		return nil, ErrFormatVersion
	}

	ephPub := wrappedDEK[1 : 1+32]
	nonce := wrappedDEK[1+32 : 1+32+NonceLen]
	ct := wrappedDEK[1+32+NonceLen:]

	symKey, err := SharedSecret(recipientPrivKey, ephPub)
	if err != nil {
		return nil, ErrDecryptFailed
	}
	defer ZeroBytes(symKey)

	return DecryptGCM(symKey, ct, nonce, nil)
}

func ReadKeyFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}
	defer ZeroBytes(data)

	trimmed := bytes.TrimSpace(data)
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return nil, fmt.Errorf("base64 decode key: %w", err)
	}
	return decoded, nil
}

func ReadKeyFromStdin() ([]byte, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return nil, fmt.Errorf("read stdin: %w", err)
	}
	defer ZeroBytes(data)

	trimmed := bytes.TrimSpace(data)
	decoded, err := base64.StdEncoding.DecodeString(string(trimmed))
	if err != nil {
		return nil, fmt.Errorf("base64 decode key: %w", err)
	}
	return decoded, nil
}

func B64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func B64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func ValidatePrincipalID(id string) error {
	if id == "" {
		return errors.New("principal ID required")
	}
	if len(id) > 128 {
		return errors.New("principal ID too long (max 128)")
	}
	return nil
}

func ValidateKeyName(name string) error {
	if name == "" {
		return errors.New("key_name required")
	}
	if len(name) > 256 {
		return errors.New("key_name too long (max 256)")
	}
	for _, c := range name {
		if c < 32 || c > 126 {
			return errors.New("key_name contains invalid characters")
		}
	}
	return nil
}

func ValidateVaultName(name string) error {
	if len(name) > 128 {
		return errors.New("vault name too long (max 128)")
	}
	return nil
}

func ValidateLimit(s string, min, max int) (int, error) {
	if s == "" {
		return 100, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < min || n > max {
		return 0, fmt.Errorf("limit must be %d-%d", min, max)
	}
	return n, nil
}
