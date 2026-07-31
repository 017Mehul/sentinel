package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/MehulChamoli/auth-service/pkg/crypto"
)

func TestGenerateBackupCodes_Count(t *testing.T) {
	plain, hashed, err := generateBackupCodes(10)
	require.NoError(t, err)
	assert.Len(t, plain, 10)
	assert.Len(t, hashed, 10)
}

func TestGenerateBackupCodes_DefaultsWhenZero(t *testing.T) {
	plain, hashed, err := generateBackupCodes(0)
	require.NoError(t, err)
	assert.Len(t, plain, 10, "should default to 10 backup codes")
	assert.Len(t, hashed, 10)
}

func TestGenerateBackupCodes_HashesAreDifferentFromPlain(t *testing.T) {
	plain, hashed, err := generateBackupCodes(5)
	require.NoError(t, err)
	for i := range plain {
		assert.NotEmpty(t, plain[i])
		assert.NotEmpty(t, hashed[i])
		assert.NotEqual(t, plain[i], hashed[i], "plain code must not equal its hash")
	}
}

func TestGenerateBackupCodes_CodesAreUnique(t *testing.T) {
	plain, hashed, err := generateBackupCodes(10)
	require.NoError(t, err)

	plainSet := make(map[string]struct{}, len(plain))
	hashSet := make(map[string]struct{}, len(hashed))
	for i := range plain {
		plainSet[plain[i]] = struct{}{}
		hashSet[hashed[i]] = struct{}{}
	}
	assert.Len(t, plainSet, 10, "plain codes must all be unique")
	assert.Len(t, hashSet, 10, "hashed codes must all be unique")
}

func TestGenerateBackupCodes_HashMatchesManualSHA256(t *testing.T) {
	plain, hashed, err := generateBackupCodes(3)
	require.NoError(t, err)

	for i := range plain {
		expected := crypto.SHA256Hex(plain[i])
		assert.Equal(t, expected, hashed[i],
			"hashed[%d] must equal SHA256Hex(plain[%d])", i, i)
	}
}

func TestGenerateBackupCodes_MultipleCalls_DifferentResults(t *testing.T) {
	plain1, _, err := generateBackupCodes(5)
	require.NoError(t, err)
	plain2, _, err := generateBackupCodes(5)
	require.NoError(t, err)

	// With high probability two independent calls produce different codes
	// (birthday collision is negligible for 5 random 8-byte hex strings)
	identical := 0
	for i := range plain1 {
		if plain1[i] == plain2[i] {
			identical++
		}
	}
	assert.Less(t, identical, 5, "two independent calls should produce different codes")
}
