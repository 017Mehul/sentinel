package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var aesKey32 = []byte("12345678901234567890123456789012")

func TestAES_EncryptDecrypt_RoundTrip(t *testing.T) {
	cases := []string{
		"hello world",
		"JBSWY3DPEHPK3PXP", // TOTP base32 seed
		"",                   // empty string is valid
		strings.Repeat("a", 1000), // large payload
	}
	for _, pt := range cases {
		ct, err := AESEncrypt(aesKey32, pt)
		require.NoError(t, err, "encrypt %q", pt)
		assert.NotEqual(t, pt, ct)

		dec, err := AESDecrypt(aesKey32, ct)
		require.NoError(t, err, "decrypt %q", pt)
		assert.Equal(t, pt, dec)
	}
}

func TestAES_Encrypt_ProducesUniqueNonce(t *testing.T) {
	// Two encryptions of the same plaintext must produce different ciphertexts
	// because GCM uses a fresh random nonce each time.
	ct1, err := AESEncrypt(aesKey32, "same-plaintext")
	require.NoError(t, err)
	ct2, err := AESEncrypt(aesKey32, "same-plaintext")
	require.NoError(t, err)
	assert.NotEqual(t, ct1, ct2, "GCM must use a fresh nonce per encryption")
}

func TestAES_Encrypt_RejectsShortKey(t *testing.T) {
	_, err := AESEncrypt([]byte("too-short"), "plaintext")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestAES_Decrypt_RejectsShortKey(t *testing.T) {
	ct, err := AESEncrypt(aesKey32, "secret")
	require.NoError(t, err)

	_, err = AESDecrypt([]byte("bad-key"), ct)
	require.Error(t, err)
}

func TestAES_Decrypt_RejectsWrongKey(t *testing.T) {
	ct, err := AESEncrypt(aesKey32, "secret")
	require.NoError(t, err)

	wrongKey := []byte("99999999999999999999999999999999")
	_, err = AESDecrypt(wrongKey, ct)
	assert.Error(t, err, "decryption with wrong key must fail")
}

func TestAES_Decrypt_RejectsTamperedCiphertext(t *testing.T) {
	ct, err := AESEncrypt(aesKey32, "secret-value")
	require.NoError(t, err)

	// Flip a character near the end (tag area)
	b := []byte(ct)
	b[len(b)-1] ^= 0xFF
	_, err = AESDecrypt(aesKey32, string(b))
	assert.Error(t, err, "GCM authentication must catch tampering")
}

func TestAES_Decrypt_RejectsInvalidBase64(t *testing.T) {
	_, err := AESDecrypt(aesKey32, "not-valid-base64!!!")
	assert.Error(t, err)
}

func TestAES_Decrypt_RejectsTooShortCiphertext(t *testing.T) {
	// Encode a slice that's shorter than the GCM nonce size (12 bytes)
	shortCT := "aGVsbG8=" // base64("hello") — only 5 bytes
	_, err := AESDecrypt(aesKey32, shortCT)
	assert.Error(t, err)
}
