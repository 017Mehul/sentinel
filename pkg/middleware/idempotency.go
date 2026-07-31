package middleware

import (
	"bytes"
	"time"

	"github.com/gin-gonic/gin"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/pkg/cache"
)

type responseWriterBuffer struct {
	gin.ResponseWriter
	body *bytes.Buffer
}

func (w *responseWriterBuffer) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

// IdempotencyMiddleware ensures idempotent requests when X-Idempotency-Key header is supplied.
func IdempotencyMiddleware(redisClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		key := c.GetHeader("X-Idempotency-Key")
		if key == "" || c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		redisKey := "idempotency:" + key

		if redisClient != nil {
			var cached []byte
			if err := redisClient.GetJSON(c.Request.Context(), redisKey, &cached); err == nil && len(cached) > 0 {
				c.Header("X-Cache", "HIT-IDEMPOTENCY")
				c.Header("Content-Type", "application/json")
				c.Writer.WriteHeader(200)
				_, _ = c.Writer.Write(cached)
				c.Abort()
				return
			}

			// Try acquiring lock (10-second TTL so orphaned locks auto-expire).
			lockKey := "lock:" + redisKey
			acquired, err := redisClient.SetNX(c.Request.Context(), lockKey, "locked", 10*time.Second)
			if err == nil && !acquired {
				response.Error(c, apperrors.ErrDuplicateRequest())
				c.Abort()
				return
			}

			defer func() {
				_ = redisClient.Delete(c.Request.Context(), lockKey)
			}()
		}

		writerBuf := &responseWriterBuffer{ResponseWriter: c.Writer, body: &bytes.Buffer{}}
		c.Writer = writerBuf

		c.Next()

		if redisClient != nil && c.Writer.Status() >= 200 && c.Writer.Status() < 300 {
			_ = redisClient.SetJSON(c.Request.Context(), redisKey, writerBuf.body.Bytes(), 24*time.Hour)
		}
	}
}
