package token

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/MehulChamoli/auth-service/config"
)

func newTestManager(t *testing.T, accessTTL time.Duration) *Manager {
	t.Helper()
	mgr, err := NewManager(&config.JWTConfig{
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-issuer",
		Audience:        "test-audience",
	})
	require.NoError(t, err)
	return mgr
}

// ── Happy path ────────────────────────────────────────────────────────────────

func TestManager_IssueAndVerify_HappyPath(t *testing.T) {
	mgr := newTestManager(t, 15*time.Minute)

	tok, claims, err := mgr.IssueAccessToken("user-abc", "session-xyz", []string{"user", "admin"})
	require.NoError(t, err)
	require.NotEmpty(t, tok)
	assert.Equal(t, "user-abc", claims.Subject)
	assert.Equal(t, "session-xyz", claims.SessionID)
	assert.Equal(t, []string{"user", "admin"}, claims.Roles)
	assert.NotEmpty(t, claims.ID, "JTI should be populated")
	assert.Equal(t, "test-issuer", claims.Issuer)

	verified, err := mgr.Verify(tok)
	require.NoError(t, err)
	assert.Equal(t, "user-abc", verified.Subject)
	assert.Equal(t, "session-xyz", verified.SessionID)
	assert.Equal(t, []string{"user", "admin"}, verified.Roles)
}

func TestManager_IssueAccessToken_EmptyRoles(t *testing.T) {
	mgr := newTestManager(t, 15*time.Minute)
	tok, claims, err := mgr.IssueAccessToken("user-1", "sess-1", []string{})
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
	assert.Empty(t, claims.Roles)

	verified, err := mgr.Verify(tok)
	require.NoError(t, err)
	// nil and empty slice are both acceptable; just verify no roles present
	assert.Empty(t, verified.Roles)
}

// ── Expiry ────────────────────────────────────────────────────────────────────

func TestManager_Verify_RejectsExpiredToken(t *testing.T) {
	mgr := newTestManager(t, -1*time.Second)

	tok, _, err := mgr.IssueAccessToken("user-1", "sess-1", []string{"user"})
	require.NoError(t, err)

	_, err = mgr.Verify(tok)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

// ── Tamper / invalid ──────────────────────────────────────────────────────────

func TestManager_Verify_RejectsTamperedSignature(t *testing.T) {
	mgr := newTestManager(t, 15*time.Minute)

	tok, _, err := mgr.IssueAccessToken("user-1", "sess-1", []string{"user"})
	require.NoError(t, err)

	// Flip a meaningful character inside the signature segment. Changing the
	// final base64url character can leave the decoded bytes unchanged because
	// its unused low bits are ignored by the decoder.
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	sig := parts[2]
	replacement := "A"
	if sig[0] == 'A' {
		replacement = "B"
	}
	parts[2] = replacement + sig[1:]
	tampered := strings.Join(parts, ".")
	_, err = mgr.Verify(tampered)
	assert.Error(t, err)
}

func TestManager_Verify_RejectsGarbage(t *testing.T) {
	mgr := newTestManager(t, 15*time.Minute)
	_, err := mgr.Verify("not.a.jwt")
	assert.Error(t, err)
}

func TestManager_Verify_RejectsEmptyString(t *testing.T) {
	mgr := newTestManager(t, 15*time.Minute)
	_, err := mgr.Verify("")
	assert.Error(t, err)
}

func TestManager_Verify_RejectsWrongIssuer(t *testing.T) {
	issuer1, err := NewManager(&config.JWTConfig{
		AccessTokenTTL: 15 * time.Minute, Issuer: "issuer-A", Audience: "api",
	})
	require.NoError(t, err)

	issuer2, err := NewManager(&config.JWTConfig{
		AccessTokenTTL: 15 * time.Minute, Issuer: "issuer-B", Audience: "api",
	})
	require.NoError(t, err)

	tok, _, err := issuer1.IssueAccessToken("u1", "s1", nil)
	require.NoError(t, err)

	// issuer2 has different private key AND different issuer claim — both fail
	_, err = issuer2.Verify(tok)
	assert.Error(t, err)
}

func TestManager_Verify_RejectsCrossKeySignature(t *testing.T) {
	mgr1 := newTestManager(t, 15*time.Minute)
	mgr2 := newTestManager(t, 15*time.Minute)

	// mgr1 issues, mgr2 (different key) tries to verify — must fail
	tok, _, err := mgr1.IssueAccessToken("u1", "s1", nil)
	require.NoError(t, err)

	// Two ephemeral managers have different randomly-generated keys
	// If they happen to share a key (extremely unlikely), skip this test
	jwks1 := mgr1.JWKS()
	jwks2 := mgr2.JWKS()
	if jwks1.Keys[0].N == jwks2.Keys[0].N {
		t.Skip("keys are identical (astronomically unlikely)")
	}

	_, err = mgr2.Verify(tok)
	assert.Error(t, err)
}

// ── JWKS ──────────────────────────────────────────────────────────────────────

func TestManager_JWKS_Structure(t *testing.T) {
	mgr := newTestManager(t, 15*time.Minute)
	jwks := mgr.JWKS()

	require.Len(t, jwks.Keys, 1)
	k := jwks.Keys[0]
	assert.Equal(t, "RSA", k.Kty)
	assert.Equal(t, "sig", k.Use)
	assert.Equal(t, "RS256", k.Alg)
	assert.NotEmpty(t, k.Kid)
	assert.NotEmpty(t, k.N, "modulus must be present")
	assert.NotEmpty(t, k.E, "exponent must be present")
	// Base64url encoding must not contain padding
	assert.False(t, strings.Contains(k.N, "="), "N must be base64url (no padding)")
	assert.False(t, strings.Contains(k.E, "="), "E must be base64url (no padding)")
}

// ── TTL helpers ───────────────────────────────────────────────────────────────

func TestManager_TTLHelpers(t *testing.T) {
	mgr, err := NewManager(&config.JWTConfig{
		AccessTokenTTL:  5 * time.Minute,
		RefreshTokenTTL: 48 * time.Hour,
		Issuer:          "x",
		Audience:        "y",
	})
	require.NoError(t, err)
	assert.Equal(t, 5*time.Minute, mgr.AccessTTL())
	assert.Equal(t, 48*time.Hour, mgr.RefreshTTL())
}

// ── Algorithm confusion guard ─────────────────────────────────────────────────

func TestManager_Verify_AlgorithmConfusionGuard(t *testing.T) {
	// This test verifies that the Verify func rejects the "alg:none" attack.
	// We manually craft a token with no signature and check it's rejected.
	// A real "none" attack would look like: header.payload.
	mgr := newTestManager(t, 15*time.Minute)

	// header {"alg":"none","typ":"JWT"} base64url encoded
	fakeToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0." +
		"eyJzdWIiOiJhdHRhY2tlciIsInNpZCI6InMxIiwicm9sZXMiOlsiYWRtaW4iXX0."

	_, err := mgr.Verify(fakeToken)
	assert.Error(t, err, "alg:none token must be rejected")
}
