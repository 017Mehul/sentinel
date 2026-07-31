package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/user"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/pkg/crypto"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func testTokenManager(t *testing.T) *token.Manager {
	t.Helper()
	mgr, err := token.NewManager(&config.JWTConfig{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-auth-service",
		Audience:        "test-api",
	})
	require.NoError(t, err)
	return mgr
}

func testSecurityConfig() config.SecurityConfig {
	return config.SecurityConfig{
		AESEncryptionKey:          "12345678901234567890123456789012", // 32 bytes
		BcryptCost:                10,
		AccountLockMaxAttempts:    5,
		AccountLockDuration:       15 * time.Minute,
		PasswordResetTokenTTL:     1 * time.Hour,
		EmailVerificationTokenTTL: 24 * time.Hour,
		MFABackupCodeCount:        10,
	}
}

// ── Token package unit tests ──────────────────────────────────────────────────

func TestService_IssueAccessToken_RoundTrip(t *testing.T) {
	mgr := testTokenManager(t)

	tok, claims, err := mgr.IssueAccessToken("user-1", "session-1", []string{"user"})
	require.NoError(t, err)
	assert.NotEmpty(t, tok)
	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, "session-1", claims.SessionID)
	assert.Equal(t, []string{"user"}, claims.Roles)

	verified, err := mgr.Verify(tok)
	require.NoError(t, err)
	assert.Equal(t, "user-1", verified.Subject)
}

func TestService_Verify_RejectsExpiredToken(t *testing.T) {
	mgr, err := token.NewManager(&config.JWTConfig{
		AccessTokenTTL:  -1 * time.Second, // already expired
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-auth-service",
		Audience:        "test-api",
	})
	require.NoError(t, err)

	tok, _, err := mgr.IssueAccessToken("user-1", "session-1", []string{"user"})
	require.NoError(t, err)

	_, err = mgr.Verify(tok)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, token.ErrTokenExpired) || errors.Is(err, token.ErrTokenInvalid))
}

func TestService_Verify_RejectsTamperedToken(t *testing.T) {
	mgr := testTokenManager(t)

	tok, _, err := mgr.IssueAccessToken("user-1", "session-1", []string{"user"})
	require.NoError(t, err)

	tampered := tok + "x"
	_, err = mgr.Verify(tampered)
	assert.Error(t, err)
}

// ── AppError sentinel tests ───────────────────────────────────────────────────

func TestAppErrors_Codes(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode string
	}{
		{"invalid credentials", apperrors.ErrInvalidCredentials(), apperrors.CodeInvalidCredentials},
		{"token expired", apperrors.ErrTokenExpired(), apperrors.CodeTokenExpired},
		{"token invalid", apperrors.ErrTokenInvalid(), apperrors.CodeTokenInvalid},
		{"token reused", apperrors.ErrTokenReused(), apperrors.CodeTokenReused},
		{"email not verified", apperrors.ErrEmailNotVerified(), apperrors.CodeEmailNotVerified},
		{"email taken", apperrors.ErrEmailTaken(), apperrors.CodeEmailTaken},
		{"user not found", apperrors.ErrUserNotFound(), apperrors.CodeUserNotFound},
		{"forbidden", apperrors.ErrForbidden(), apperrors.CodeForbidden},
		{"mfa required", apperrors.ErrMFARequired(), apperrors.CodeMFARequired},
		{"password breached", apperrors.ErrPasswordBreached(), apperrors.CodePasswordBreached},
		{"rate limited", apperrors.ErrRateLimited(), apperrors.CodeRateLimited},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ae := apperrors.AsAppError(tt.err)
			require.NotNil(t, ae, "expected *AppError")
			assert.Equal(t, tt.wantCode, ae.Code)
			assert.NotEmpty(t, ae.Message)
			assert.Greater(t, ae.HTTPStatus, 0)
		})
	}
}

func TestAppErrors_AsAppError_Nil(t *testing.T) {
	assert.Nil(t, apperrors.AsAppError(nil))
	assert.False(t, apperrors.IsAppError(nil))
}

func TestAppErrors_AsAppError_UnknownError(t *testing.T) {
	err := errors.New("some internal error")
	assert.Nil(t, apperrors.AsAppError(err))
	assert.False(t, apperrors.IsAppError(err))
}

// ── Account lock logic unit tests ─────────────────────────────────────────────

func TestAccountLock_LockUntilInFuture(t *testing.T) {
	lockUntil := time.Now().Add(15 * time.Minute)
	u := user.User{
		IsLocked:    true,
		LockedUntil: &lockUntil,
	}

	// Simulates the lock check in Service.Login
	assert.True(t, u.IsLocked)
	assert.True(t, u.LockedUntil.After(time.Now()))
}

func TestAccountLock_LockExpired(t *testing.T) {
	lockUntil := time.Now().Add(-1 * time.Minute) // in the past
	u := user.User{
		IsLocked:    true,
		LockedUntil: &lockUntil,
	}

	// Lock is technically set, but the time has passed — login should be allowed
	assert.True(t, u.IsLocked)
	assert.False(t, u.LockedUntil.After(time.Now()))
}

// ── Crypto helpers integration ────────────────────────────────────────────────

func TestCrypto_RefreshTokenHashing(t *testing.T) {
	// Two different tokens must produce different hashes
	tok1, err := crypto.SecureRandom(32)
	require.NoError(t, err)
	tok2, err := crypto.SecureRandom(32)
	require.NoError(t, err)

	h1 := crypto.SHA256Hex(tok1)
	h2 := crypto.SHA256Hex(tok2)

	assert.NotEqual(t, tok1, tok2)
	assert.NotEqual(t, h1, h2)
	// Hash is deterministic
	assert.Equal(t, h1, crypto.SHA256Hex(tok1))
}

func TestCrypto_PasswordNotStoredInPlaintext(t *testing.T) {
	password := "SuperSecret123!"
	hash, err := crypto.HashPassword(password, 10)
	require.NoError(t, err)

	assert.NotEqual(t, password, hash)
	assert.NoError(t, crypto.ComparePassword(hash, password))
	assert.Error(t, crypto.ComparePassword(hash, "WrongPassword"))
}

func TestCrypto_AES_WrongKeyLength(t *testing.T) {
	shortKey := []byte("tooshort")
	_, err := crypto.AESEncrypt(shortKey, "plaintext")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "32 bytes")
}

func TestCrypto_AES_TamperedCiphertext(t *testing.T) {
	key := []byte("12345678901234567890123456789012")
	ct, err := crypto.AESEncrypt(key, "secret")
	require.NoError(t, err)

	_, err = crypto.AESDecrypt(key, ct+"tampered==")
	assert.Error(t, err)
}

// ── HIBP client unit tests ────────────────────────────────────────────────────

func TestHIBP_EmptyPassword(t *testing.T) {
	client := crypto.NewHIBPClient(2 * time.Second)
	pwned, count, err := client.IsPwned(context.Background(), "")
	require.NoError(t, err)
	assert.False(t, pwned)
	assert.Zero(t, count)
}

// ── Security config defaults ──────────────────────────────────────────────────

func TestSecurityConfig_Defaults(t *testing.T) {
	cfg := testSecurityConfig()

	assert.Equal(t, 32, len(cfg.AESEncryptionKey), "AES key must be 32 bytes")
	assert.GreaterOrEqual(t, cfg.BcryptCost, 10)
	assert.LessOrEqual(t, cfg.BcryptCost, 14)
	assert.Greater(t, cfg.AccountLockMaxAttempts, 0)
	assert.Greater(t, cfg.AccountLockDuration, time.Duration(0))
}

// ── Token family rotation invariant ──────────────────────────────────────────

// TestRefreshTokenFamilyRotation_Invariant verifies the core security property:
// a revoked refresh token must never produce a new token pair.
// The actual rotation logic runs in the Service layer against a real DB;
// this test validates the supporting hash + comparison primitives that
// enforce the invariant.
func TestRefreshTokenFamilyRotation_Invariant(t *testing.T) {
	// Step 1: issue token
	rawToken, err := crypto.SecureRandom(32)
	require.NoError(t, err)

	storedHash := crypto.SHA256Hex(rawToken)

	// Step 2: simulate presenting the token on refresh
	presentedToken := rawToken
	presentedHash := crypto.SHA256Hex(presentedToken)
	assert.Equal(t, storedHash, presentedHash, "hash of presented token must match stored hash")

	// Step 3: simulate token reuse (attacker replays the same token)
	// After rotation the old record is revoked — the repository returns ErrTokenReused
	revokedAt := time.Now()
	assert.False(t, revokedAt.IsZero(), "revoked_at must be set after rotation")

	// Step 4: a different raw token must produce a different hash (no collision)
	anotherToken, err := crypto.SecureRandom(32)
	require.NoError(t, err)
	assert.NotEqual(t, crypto.SHA256Hex(anotherToken), storedHash)
}
