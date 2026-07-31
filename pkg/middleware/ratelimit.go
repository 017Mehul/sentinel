package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"github.com/MehulChamoli/auth-service/config"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/pkg/cache"
)

// RateLimiter creates a rate limiting middleware using Redis.
func RateLimiter(c *cache.Client, rpm int, window time.Duration, keyPrefix string) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		if c == nil || rpm <= 0 {
			ctx.Next()
			return
		}

		clientIP := ctx.ClientIP()
		key := fmt.Sprintf("ratelimit:%s:%s", keyPrefix, clientIP)

		count, err := c.IncrWithExpire(ctx.Request.Context(), key, window)
		if err != nil {
			// Fail open to avoid blocking legitimate requests, but emit a
			// warn-level log so operators can detect and alert on degradation.
			log.Warn().Err(err).Str("key_prefix", keyPrefix).Str("client_ip", clientIP).
				Msg("rate limiter: Redis error, failing open")
			ctx.Next()
			return
		}

		ctx.Header("X-RateLimit-Limit", strconv.Itoa(rpm))
		remaining := rpm - int(count)
		if remaining < 0 {
			remaining = 0
		}
		ctx.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))

		if count > int64(rpm) {
			response.Error(ctx, apperrors.ErrRateLimited())
			ctx.AbortWithStatus(http.StatusTooManyRequests)
			return
		}

		ctx.Next()
	}
}

// RateLimitMiddleware returns a Gin middleware configured via RateLimitConfig.
func RateLimitMiddleware(cfg *config.RateLimitConfig, redisClient *cache.Client, authRPM bool) gin.HandlerFunc {
	if cfg == nil || !cfg.Enabled {
		return func(c *gin.Context) {
			c.Next()
		}
	}

	rpm := cfg.GeneralRPM
	prefix := "gen"
	if authRPM {
		rpm = cfg.AuthRPM
		prefix = "auth"
	}
	window := cfg.Window
	if window <= 0 {
		window = time.Minute
	}

	return RateLimiter(redisClient, rpm, window, prefix)
}
