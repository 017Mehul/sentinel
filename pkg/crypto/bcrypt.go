package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword hashes a plaintext password using bcrypt at the given cost.
// Cost should be between 10-14; 12 is a reasonable production default.
func HashPassword(password string, cost int) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", fmt.Errorf("hashing password: %w", err)
	}
	return string(hash), nil
}

// ComparePassword returns nil if plaintext matches the bcrypt hash.
// It returns an error if the comparison fails or the hash is invalid.
func ComparePassword(hash, plaintext string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
}

// SecureRandom generates n cryptographically secure random bytes and returns
// them as a hex string (length = n*2).
func SecureRandom(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// SHA256Hex returns the lowercase hex-encoded SHA-256 hash of s.
// Used for token hashing before database storage (never store raw tokens).
func SHA256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ConstantTimeCompare performs a constant-time comparison of two strings
// to prevent timing attacks (e.g., HMAC verification, token comparison).
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
