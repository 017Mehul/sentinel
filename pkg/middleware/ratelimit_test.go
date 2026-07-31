package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/MehulChamoli/auth-service/config"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// newTestRouter creates a minimal Gin engine with the given middleware and a
// single GET /ping handler that always returns 200.
func newTestRouter(mw gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(mw)
	r.GET("/ping", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func TestRateLimitMiddleware_DisabledConfig_PassesThrough(t *testing.T) {
	mw := RateLimitMiddleware(&config.RateLimitConfig{Enabled: false}, nil, false)
	r := newTestRouter(mw)

	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ping", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code, "request %d should pass when rate limit is disabled", i+1)
	}
}

func TestRateLimitMiddleware_NilConfig_PassesThrough(t *testing.T) {
	mw := RateLimitMiddleware(nil, nil, false)
	r := newTestRouter(mw)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestRateLimitMiddleware_NilRedis_FailsOpen(t *testing.T) {
	// When Redis is nil (RateLimiter skips), requests should pass through
	mw := RateLimitMiddleware(&config.RateLimitConfig{
		Enabled:    true,
		GeneralRPM: 10,
		Window:     time.Minute,
	}, nil, false)
	r := newTestRouter(mw)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIdempotencyMiddleware_SkipsGET(t *testing.T) {
	// Idempotency key on a GET request should be ignored
	mw := IdempotencyMiddleware(nil)
	r := newTestRouter(mw)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("X-Idempotency-Key", "test-key-123")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIdempotencyMiddleware_NoKey_PassesThrough(t *testing.T) {
	// No idempotency key — middleware is a no-op
	mw := IdempotencyMiddleware(nil)
	r := newTestRouter(mw)

	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestIdempotencyMiddleware_NilRedis_PassesThrough(t *testing.T) {
	// When Redis is nil the middleware must not block the request
	mw := IdempotencyMiddleware(nil)
	r := newTestRouter(mw)

	req := httptest.NewRequest(http.MethodPost, "/ping", nil)
	req.Header.Set("X-Idempotency-Key", "idem-key-abc")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}
