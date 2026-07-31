package token

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/MehulChamoli/auth-service/config"
)

func TestJWTManager_IssueAndVerify(t *testing.T) {
	cfg := &config.JWTConfig{
		PrivateKeyPath:  "",
		PublicKeyPath:   "",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-auth-service",
		Audience:        "test-api",
	}

	mgr, err := NewManager(cfg)
	require.NoError(t, err)
	require.NotNil(t, mgr)

	userID := "user-123"
	sessionID := "session-456"
	roles := []string{"user", "admin"}

	tokenStr, claims, err := mgr.IssueAccessToken(userID, sessionID, roles)
	require.NoError(t, err)
	assert.NotEmpty(t, tokenStr)
	assert.Equal(t, userID, claims.Subject)
	assert.Equal(t, sessionID, claims.SessionID)
	assert.Equal(t, roles, claims.Roles)

	verifiedClaims, err := mgr.Verify(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, userID, verifiedClaims.Subject)
	assert.Equal(t, sessionID, verifiedClaims.SessionID)
	assert.Equal(t, roles, verifiedClaims.Roles)
}

func TestJWTManager_JWKS(t *testing.T) {
	cfg := &config.JWTConfig{
		Issuer:   "test-auth-service",
		Audience: "test-api",
	}

	mgr, err := NewManager(cfg)
	require.NoError(t, err)

	jwks := mgr.JWKS()
	assert.Len(t, jwks.Keys, 1)
	assert.Equal(t, "RSA", jwks.Keys[0].Kty)
	assert.Equal(t, "RS256", jwks.Keys[0].Alg)
	assert.NotEmpty(t, jwks.Keys[0].N)
	assert.NotEmpty(t, jwks.Keys[0].E)
}
