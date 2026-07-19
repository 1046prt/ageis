package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptGCM(t *testing.T) {
	key := make([]byte, DEKLen)
	for i := range key {
		key[i] = byte(i)
	}

	plaintext := []byte("super-secret-password-12345")
	aad := []byte("vault-abc/secret-xyz")

	ct, nonce, err := EncryptGCM(key, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptGCM: %v", err)
	}
	if bytes.Equal(ct, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	got, err := DecryptGCM(key, ct, nonce, aad)
	if err != nil {
		t.Fatalf("DecryptGCM: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecryptGCMWrongKey(t *testing.T) {
	key := make([]byte, DEKLen)
	wrongKey := make([]byte, DEKLen)
	wrongKey[0] = 1

	ct, nonce, err := EncryptGCM(key, []byte("data"), nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptGCM(wrongKey, ct, nonce, nil)
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptGCMWrongNonce(t *testing.T) {
	key := make([]byte, DEKLen)
	ct, nonce, err := EncryptGCM(key, []byte("data"), nil)
	if err != nil {
		t.Fatal(err)
	}

	wrongNonce := make([]byte, len(nonce))
	wrongNonce[0] = 1

	_, err = DecryptGCM(key, ct, wrongNonce, nil)
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestDecryptGCMWrongAAD(t *testing.T) {
	key := make([]byte, DEKLen)
	ct, nonce, err := EncryptGCM(key, []byte("data"), []byte("aad1"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptGCM(key, ct, nonce, []byte("aad2"))
	if err != ErrDecryptFailed {
		t.Fatalf("expected ErrDecryptFailed, got %v", err)
	}
}

func TestX25519SharedSecret(t *testing.T) {
	alice, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bob, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	secretA, err := SharedSecret(alice.PrivateKey[:], bob.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	secretB, err := SharedSecret(bob.PrivateKey[:], alice.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(secretA, secretB) {
		t.Fatal("ECDH shared secrets do not match")
	}
	if len(secretA) != DEKLen {
		t.Fatalf("shared secret length: got %d, want %d", len(secretA), DEKLen)
	}
}

func TestWrapUnwrapDEK(t *testing.T) {
	recipient, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	dek := make([]byte, DEKLen)
	for i := range dek {
		dek[i] = byte(i + 0x10)
	}

	wrapped, err := WrapDEK(dek, recipient.PublicKey[:])
	if err != nil {
		t.Fatalf("WrapDEK: %v", err)
	}
	if bytes.Equal(wrapped, dek) {
		t.Fatal("wrapped DEK equals raw DEK")
	}

	got, err := UnwrapDEK(wrapped, recipient.PrivateKey[:])
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapped DEK does not match original")
	}
}

func TestUnwrapDEKWrongKey(t *testing.T) {
	recipient, _ := GenerateX25519KeyPair()
	wrongRecipient, _ := GenerateX25519KeyPair()

	wrapped, _ := WrapDEK(make([]byte, DEKLen), recipient.PublicKey[:])

	_, err := UnwrapDEK(wrapped, wrongRecipient.PrivateKey[:])
	if err == nil {
		t.Fatal("expected error unwrapping with wrong key")
	}
}

func TestUnwrapDEKTooShort(t *testing.T) {
	_, err := UnwrapDEK([]byte("short"), make([]byte, 32))
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey, got %v", err)
	}
}

func TestDeriveMasterKey(t *testing.T) {
	salt := make([]byte, SaltLen)
	for i := range salt {
		salt[i] = byte(i)
	}
	mk1 := DeriveMasterKey("password123", salt)
	mk2 := DeriveMasterKey("password123", salt)
	if !bytes.Equal(mk1, mk2) {
		t.Fatal("same password+salt should produce same key")
	}
	mk3 := DeriveMasterKey("different", salt)
	if bytes.Equal(mk1, mk3) {
		t.Fatal("different passwords should produce different keys")
	}
	if len(mk1) != DEKLen {
		t.Fatalf("master key length: got %d, want %d", len(mk1), DEKLen)
	}
}

func TestNewSalt(t *testing.T) {
	s1, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := NewSalt()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, s2) {
		t.Fatal("two salts should not be equal")
	}
	if len(s1) != SaltLen {
		t.Fatalf("salt length: got %d, want %d", len(s1), SaltLen)
	}
}

func TestGenerateID(t *testing.T) {
	id1, err := GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := GenerateID()
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatal("two IDs should not be equal")
	}
	if len(id1) < 20 {
		t.Fatalf("ID too short: %q", id1)
	}
}

func TestB64Roundtrip(t *testing.T) {
	data := []byte("hello world \x00\xff")
	encoded := B64Encode(data)
	decoded, err := B64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, data) {
		t.Fatal("base64 roundtrip failed")
	}
}

func TestZeroBytes(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("byte %d not zeroed: %d", i, v)
		}
	}
}

func BenchmarkEncryptGCM(b *testing.B) {
	key := make([]byte, DEKLen)
	plaintext := make([]byte, 1024)
	for i := range plaintext {
		plaintext[i] = byte(i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		EncryptGCM(key, plaintext, nil)
	}
}

func BenchmarkWrapDEK(b *testing.B) {
	recipient, _ := GenerateX25519KeyPair()
	dek := make([]byte, DEKLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		WrapDEK(dek, recipient.PublicKey[:])
	}
}

func BenchmarkDeriveMasterKey(b *testing.B) {
	salt := make([]byte, SaltLen)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		DeriveMasterKey("password", salt)
	}
}
