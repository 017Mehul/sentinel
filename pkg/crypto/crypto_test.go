package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordHashing(t *testing.T) {
	password := "SecretPassword123!"

	hash, err := HashPassword(password, 10)
	require.NoError(t, err)
	assert.NotEmpty(t, hash)

	err = ComparePassword(hash, password)
	assert.NoError(t, err)

	err = ComparePassword(hash, "WrongPassword!")
	assert.Error(t, err)
}

func TestAESEncryptionDecryption(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes AES-256
	plaintext := "SecretTOTPSeedABCXYZ"

	ciphertext, err := AESEncrypt(key, plaintext)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	decrypted, err := AESDecrypt(key, ciphertext)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestSHA256Hex(t *testing.T) {
	raw := "token_string_123"
	hash1 := SHA256Hex(raw)
	hash2 := SHA256Hex(raw)

	assert.NotEmpty(t, hash1)
	assert.Equal(t, hash1, hash2)
	assert.NotEqual(t, raw, hash1)
}

func TestSecureRandom(t *testing.T) {
	randStr1, err := SecureRandom(16)
	require.NoError(t, err)
	assert.NotEmpty(t, randStr1)

	randStr2, err := SecureRandom(16)
	require.NoError(t, err)
	assert.NotEqual(t, randStr1, randStr2)
}
