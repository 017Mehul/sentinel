//go:build integration
// +build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/admin"
	"github.com/MehulChamoli/auth-service/internal/api"
	"github.com/MehulChamoli/auth-service/internal/auth"
	"github.com/MehulChamoli/auth-service/internal/mfa"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/pkg/cache"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

// testEnv holds all wired-up components for an integration test run.
type testEnv struct {
	router *api.Router
	pool   *pgxpool.Pool
	redis  *cache.Client
}

// setupTestEnv spins up Postgres + Redis containers, runs migrations, and
// returns a fully wired router ready to serve requests.
func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	// ── Postgres ──────────────────────────────────────────────────────────────
	pgC, err := tcpostgres.Run(ctx,
		"postgres:16-alpine",
		tcpostgres.WithDatabase("authdb"),
		tcpostgres.WithUsername("postgres"),
		tcpostgres.WithPassword("password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(30*time.Second)),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgC.Terminate(ctx) })

	pgDSN, err := pgC.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	// ── Redis ─────────────────────────────────────────────────────────────────
	redisC, err := tcredis.Run(ctx,
		"redis:7-alpine",
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections")),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisC.Terminate(ctx) })

	redisAddr, err := redisC.ConnectionString(ctx)
	require.NoError(t, err)
	// Strip "redis://" prefix that testcontainers-go/modules/redis returns
	redisAddr = stripPrefix(redisAddr, "redis://")

	// ── Database pool ─────────────────────────────────────────────────────────
	pool, err := pgxpool.New(ctx, pgDSN)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	// ── Run migrations ────────────────────────────────────────────────────────
	runMigrations(t, ctx, pool)

	// ── Redis client ──────────────────────────────────────────────────────────
	redisClient, err := cache.NewRedisClient(&config.RedisConfig{
		Addr:         redisAddr,
		PoolSize:     5,
		MinIdleConns: 1,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = redisClient.Close() })

	// ── Token manager ─────────────────────────────────────────────────────────
	tokenMgr, err := token.NewManager(&config.JWTConfig{
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		Issuer:          "test-auth",
		Audience:        "test-api",
	})
	require.NoError(t, err)

	// ── Wire up service graph ─────────────────────────────────────────────────
	sec := &config.SecurityConfig{
		AESEncryptionKey:          "12345678901234567890123456789012",
		BcryptCost:                10, // low cost for tests
		AccountLockMaxAttempts:    3,
		AccountLockDuration:       1 * time.Minute,
		PasswordResetTokenTTL:     1 * time.Hour,
		EmailVerificationTokenTTL: 24 * time.Hour,
		MFABackupCodeCount:        10,
	}

	userRepo := user.NewRepository(pool)
	userSvc := user.NewService(userRepo)
	userHandler := user.NewHandler(userSvc)

	mfaRepo := mfa.NewRepository(pool)
	mfaSvc := mfa.NewService(mfaRepo, userRepo, sec)
	mfaHandler := mfa.NewHandler(mfaSvc)

	adminRepo := admin.NewRepository(pool)
	adminSvc := admin.NewService(adminRepo)
	adminHandler := admin.NewHandler(adminSvc)

	authRepo := auth.NewRepository(pool)
	authSvc := auth.NewService(authRepo, userRepo, mfaSvc, redisClient, tokenMgr, sec, "test")
	authHandler := auth.NewHandler(authSvc)

	cfg := &config.Config{
		App: config.AppConfig{Name: "test", Env: "test", Version: "0.0.1"},
		RateLimit: config.RateLimitConfig{Enabled: false},
		CORS:      config.CORSConfig{AllowedOrigins: []string{"*"}},
	}

	router := api.NewRouter(cfg, tokenMgr, authHandler, userHandler, adminHandler, mfaHandler, nil, pool, redisClient, nil)

	return &testEnv{router: router, pool: pool, redis: redisClient}
}

// runMigrations applies all SQL up-migrations from the migrations directory.
func runMigrations(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	// Read and execute migrations in order using golang-migrate via exec.
	// For integration tests we drive them directly via SQL files to avoid
	// requiring the migrate CLI binary inside the test runner.
	migrations := []string{
		"../../migrations/000001_create_users.up.sql",
		"../../migrations/000002_create_roles_permissions.up.sql",
		"../../migrations/000003_create_refresh_tokens.up.sql",
		"../../migrations/000004_create_sessions.up.sql",
		"../../migrations/000005_create_login_history.up.sql",
		"../../migrations/000006_create_password_reset_tokens.up.sql",
		"../../migrations/000007_create_email_verification_tokens.up.sql",
		"../../migrations/000008_create_oauth_accounts.up.sql",
		"../../migrations/000009_create_audit_logs.up.sql",
		"../../migrations/000010_create_mfa.up.sql",
		"../../migrations/000011_create_outbox_events.up.sql",
		"../../migrations/000012_create_idempotency_keys.up.sql",
		"../../migrations/000013_create_webhooks.up.sql",
		"../../migrations/000014_seed_rbac.up.sql",
	}
	for _, path := range migrations {
		sql, err := readFile(path)
		require.NoError(t, err, "reading migration %s", path)
		if sql == "" {
			continue
		}
		_, err = pool.Exec(ctx, sql)
		require.NoError(t, err, "applying migration %s", path)
	}
}

// ── Test helpers ──────────────────────────────────────────────────────────────

func postJSON(t *testing.T, router http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func postJSONAuth(t *testing.T, router http.Handler, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func getJSON(t *testing.T, router http.Handler, path, bearerToken string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&out))
	return out
}

func stripPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("readFile %s: %w", path, err)
	}
	return string(b), nil
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestIntegration_Register_And_Login exercises the full registration → email
// verification → login flow against real Postgres + Redis containers.
func TestIntegration_Register_And_Login(t *testing.T) {
	env := setupTestEnv(t)

	// 1. Register
	rec := postJSON(t, env.router, "/api/v1/auth/register", map[string]any{
		"email":     "alice@example.com",
		"password":  "SecurePass123!",
		"full_name": "Alice Example",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	body := decodeBody(t, rec)
	data := body["data"].(map[string]any)
	verifyToken, ok := data["email_verification_token"].(string)
	require.True(t, ok, "email_verification_token must be present")
	assert.NotEmpty(t, verifyToken)

	// 2. Login before verifying email → should fail
	rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"email":    "alice@example.com",
		"password": "SecurePass123!",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	errBody := decodeBody(t, rec)
	assert.Equal(t, "AUTH_007", errBody["error"].(map[string]any)["code"])

	// 3. Verify email
	rec = postJSON(t, env.router, "/api/v1/auth/verify-email", map[string]any{
		"token": verifyToken,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 4. Login → should succeed
	rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"email":    "alice@example.com",
		"password": "SecurePass123!",
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	loginData := decodeBody(t, rec)["data"].(map[string]any)
	accessToken := loginData["access_token"].(string)
	refreshToken := loginData["refresh_token"].(string)
	assert.NotEmpty(t, accessToken)
	assert.NotEmpty(t, refreshToken)

	// 5. Access protected endpoint /users/me
	rec = getJSON(t, env.router, "/api/v1/users/me", accessToken)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	meData := decodeBody(t, rec)["data"].(map[string]any)
	assert.Equal(t, "alice@example.com", meData["user"].(map[string]any)["email"])
}

// TestIntegration_Login_WrongPassword verifies that invalid credentials return
// the correct error code and HTTP status.
func TestIntegration_Login_WrongPassword(t *testing.T) {
	env := setupTestEnv(t)

	// Register + verify
	rec := postJSON(t, env.router, "/api/v1/auth/register", map[string]any{
		"email": "bob@example.com", "password": "RightPass123!", "full_name": "Bob",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	token := decodeBody(t, rec)["data"].(map[string]any)["email_verification_token"].(string)
	rec = postJSON(t, env.router, "/api/v1/auth/verify-email", map[string]any{"token": token})
	require.Equal(t, http.StatusOK, rec.Code)

	// Wrong password
	rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"email": "bob@example.com", "password": "WrongPass!",
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, "AUTH_001", decodeBody(t, rec)["error"].(map[string]any)["code"])
}

// TestIntegration_AccountLockout verifies progressive lockout after N failures.
func TestIntegration_AccountLockout(t *testing.T) {
	env := setupTestEnv(t)

	// Register + verify
	rec := postJSON(t, env.router, "/api/v1/auth/register", map[string]any{
		"email": "charlie@example.com", "password": "RightPass123!", "full_name": "Charlie",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	vt := decodeBody(t, rec)["data"].(map[string]any)["email_verification_token"].(string)
	rec = postJSON(t, env.router, "/api/v1/auth/verify-email", map[string]any{"token": vt})
	require.Equal(t, http.StatusOK, rec.Code)

	// 3 failed attempts (matches AccountLockMaxAttempts in setupTestEnv)
	for i := 0; i < 3; i++ {
		rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
			"email": "charlie@example.com", "password": "WrongPass!",
		})
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "attempt %d", i+1)
	}

	// Next attempt should be locked (423)
	rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"email": "charlie@example.com", "password": "RightPass123!",
	})
	assert.Equal(t, http.StatusLocked, rec.Code)
	assert.Equal(t, "AUTH_002", decodeBody(t, rec)["error"].(map[string]any)["code"])
}

// TestIntegration_TokenRefreshRotation verifies that:
//  1. A refresh token can be exchanged for a new access+refresh pair.
//  2. Reusing the original (now-revoked) refresh token is rejected.
func TestIntegration_TokenRefreshRotation(t *testing.T) {
	env := setupTestEnv(t)

	// Register + verify + login
	rec := postJSON(t, env.router, "/api/v1/auth/register", map[string]any{
		"email": "dave@example.com", "password": "MyPass123!", "full_name": "Dave",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	vt := decodeBody(t, rec)["data"].(map[string]any)["email_verification_token"].(string)
	rec = postJSON(t, env.router, "/api/v1/auth/verify-email", map[string]any{"token": vt})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"email": "dave@example.com", "password": "MyPass123!",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	d := decodeBody(t, rec)["data"].(map[string]any)
	originalRefresh := d["refresh_token"].(string)

	// Refresh → get new pair
	rec = postJSON(t, env.router, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": originalRefresh,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	newData := decodeBody(t, rec)["data"].(map[string]any)
	newRefresh := newData["refresh_token"].(string)
	assert.NotEmpty(t, newRefresh)
	assert.NotEqual(t, originalRefresh, newRefresh, "new token must differ from original")

	// Replay original refresh token → must be rejected (token reuse attack)
	rec = postJSON(t, env.router, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": originalRefresh,
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "replayed token must be rejected")
	assert.Equal(t, "AUTH_004", decodeBody(t, rec)["error"].(map[string]any)["code"])
}

// TestIntegration_Logout verifies that logging out invalidates the refresh token.
func TestIntegration_Logout(t *testing.T) {
	env := setupTestEnv(t)

	rec := postJSON(t, env.router, "/api/v1/auth/register", map[string]any{
		"email": "eve@example.com", "password": "EvePwd123!", "full_name": "Eve",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	vt := decodeBody(t, rec)["data"].(map[string]any)["email_verification_token"].(string)
	postJSON(t, env.router, "/api/v1/auth/verify-email", map[string]any{"token": vt})

	rec = postJSON(t, env.router, "/api/v1/auth/login", map[string]any{
		"email": "eve@example.com", "password": "EvePwd123!",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	d := decodeBody(t, rec)["data"].(map[string]any)
	refreshToken := d["refresh_token"].(string)
	accessToken := d["access_token"].(string)

	// Logout
	rec = postJSONAuth(t, env.router, "/api/v1/auth/logout", accessToken, map[string]any{
		"refresh_token": refreshToken,
	})
	assert.Equal(t, http.StatusNoContent, rec.Code)

	// Refresh after logout → must fail
	rec = postJSON(t, env.router, "/api/v1/auth/refresh", map[string]any{
		"refresh_token": refreshToken,
	})
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestIntegration_DuplicateEmail verifies that registering the same email twice
// returns the correct conflict error.
func TestIntegration_DuplicateEmail(t *testing.T) {
	env := setupTestEnv(t)

	payload := map[string]any{
		"email": "frank@example.com", "password": "FrankPwd1!", "full_name": "Frank",
	}
	rec := postJSON(t, env.router, "/api/v1/auth/register", payload)
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = postJSON(t, env.router, "/api/v1/auth/register", payload)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Equal(t, "USER_002", decodeBody(t, rec)["error"].(map[string]any)["code"])
}

// TestIntegration_HealthEndpoints verifies the system endpoints respond correctly.
func TestIntegration_HealthEndpoints(t *testing.T) {
	env := setupTestEnv(t)

	rec := getJSON(t, env.router, "/healthz", "")
	assert.Equal(t, http.StatusOK, rec.Code)

	rec = getJSON(t, env.router, "/.well-known/jwks.json", "")
	assert.Equal(t, http.StatusOK, rec.Code)
	var jwks map[string]any
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&jwks))
	keys, ok := jwks["keys"].([]any)
	require.True(t, ok)
	assert.Len(t, keys, 1)
}
