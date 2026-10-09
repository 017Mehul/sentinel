package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/admin"
	"github.com/MehulChamoli/auth-service/internal/auth"
	"github.com/MehulChamoli/auth-service/internal/mfa"
	"github.com/MehulChamoli/auth-service/internal/oauth"
	"github.com/MehulChamoli/auth-service/internal/shared/contextkeys"
	apperrors "github.com/MehulChamoli/auth-service/internal/shared/errors"
	"github.com/MehulChamoli/auth-service/internal/shared/response"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/pkg/cache"
	"github.com/MehulChamoli/auth-service/pkg/database"
	"github.com/MehulChamoli/auth-service/pkg/metrics"
	"github.com/MehulChamoli/auth-service/pkg/middleware"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

// Router wraps the Gin engine and mounts the service endpoints.
type Router struct {
	*gin.Engine
	cfg      *config.Config
	tokenMgr *token.Manager
	auth     *auth.Handler
	users    *user.Handler
	admin    *admin.Handler
	mfa      *mfa.Handler
	oauth    *oauth.Handler
	db       *pgxpool.Pool
	redis    *cache.Client
	metrics  *metrics.Collector
}

// NewRouter creates the HTTP router used by the auth service.
func NewRouter(cfg *config.Config, tokenMgr *token.Manager, authHandler *auth.Handler, userHandler *user.Handler, adminHandler *admin.Handler, mfaHandler *mfa.Handler, oauthHandler *oauth.Handler, db *pgxpool.Pool, redis *cache.Client, metricsCollector *metrics.Collector) *Router {
	engine := gin.New()
	_ = engine.SetTrustedProxies(nil)
	engine.Use(gin.Recovery())
	engine.Use(requestIDMiddleware())
	engine.Use(corsMiddleware(cfg))
	engine.Use(middleware.RateLimitMiddleware(&cfg.RateLimit, redis, false))
	engine.Use(middleware.IdempotencyMiddleware(redis))

	r := &Router{
		Engine:   engine,
		cfg:      cfg,
		tokenMgr: tokenMgr,
		auth:     authHandler,
		users:    userHandler,
		admin:    adminHandler,
		mfa:      mfaHandler,
		oauth:    oauthHandler,
		db:       db,
		redis:    redis,
		metrics:  metricsCollector,
	}

	r.mountSystemRoutes()
	r.mountAPIRoutes()
	return r
}

func (r *Router) mountSystemRoutes() {
	r.GET("/healthz", func(c *gin.Context) {
		response.OK(c, gin.H{
			"status":  "ok",
			"service": r.cfg.App.Name,
		})
	})

	r.GET("/ready", func(c *gin.Context) {
		if err := database.HealthCheck(c.Request.Context(), r.db); err != nil {
			response.Error(c, apperrors.ErrServiceUnavailable("database unavailable"))
			return
		}
		if r.redis != nil {
			if err := r.redis.Ping(c.Request.Context()); err != nil {
				response.Error(c, apperrors.ErrServiceUnavailable("redis unavailable"))
				return
			}
		}
		response.OK(c, gin.H{"status": "ready"})
	})

	r.GET("/version", func(c *gin.Context) {
		response.OK(c, gin.H{
			"name":    r.cfg.App.Name,
			"version": r.cfg.App.Version,
			"env":     r.cfg.App.Env,
		})
	})

	r.GET("/.well-known/jwks.json", func(c *gin.Context) {
		r.tokenMgr.ServeJWKS(c.Writer)
	})

	if r.metrics != nil {
		r.GET("/metrics", gin.WrapH(r.metrics.Handler()))
	}
}

func (r *Router) mountAPIRoutes() {
	v1 := r.Group("/api/v1")

	auth := v1.Group("/auth")
	auth.Use(middleware.RateLimitMiddleware(&r.cfg.RateLimit, r.redis, true))
	auth.POST("/login", r.auth.Login)
	auth.POST("/register", r.auth.Register)
	auth.POST("/verify-email", r.auth.VerifyEmail)
	auth.POST("/forgot-password", r.auth.ForgotPassword)
	auth.POST("/reset-password", r.auth.ResetPassword)
	auth.POST("/refresh", r.auth.Refresh)
	auth.POST("/logout", r.auth.Logout)

	users := v1.Group("/users")
	users.Use(r.authMiddleware())
	users.GET("/me", r.users.Me)
	users.PATCH("/me", r.users.UpdateMe)

	sessions := v1.Group("/sessions")
	sessions.Use(r.authMiddleware())
	sessions.GET("", r.auth.ListSessions)
	sessions.DELETE("/current", r.auth.RevokeCurrentSession)

	admin := v1.Group("/admin")
	admin.Use(r.authMiddleware())
	admin.GET("/roles", r.admin.ListRoles)
	admin.GET("/permissions", r.admin.ListPermissions)
	admin.GET("/audit-logs", r.admin.ListAuditLogs)
	admin.POST("/users/roles", r.admin.AssignRole)
	admin.DELETE("/users/roles", r.admin.RemoveRole)

	mfa := v1.Group("/mfa")
	mfa.Use(r.authMiddleware())
	mfa.POST("/setup", r.mfa.Setup)
	mfa.POST("/enable", r.mfa.Enable)
	mfa.POST("/disable", r.mfa.Disable)

	oauth := v1.Group("/oauth")
	if r.oauth != nil {
		oauth.GET("/google/login", r.oauth.GoogleLogin)
		oauth.GET("/github/login", r.oauth.GitHubLogin)
		oauth.GET("/google/callback", r.oauth.GoogleCallback)
		oauth.GET("/github/callback", r.oauth.GitHubCallback)
	} else {
		oauth.GET("/google/login", notImplemented)
		oauth.GET("/github/login", notImplemented)
		oauth.GET("/google/callback", notImplemented)
		oauth.GET("/github/callback", notImplemented)
	}
}

func requestIDMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		requestID := c.GetHeader("X-Request-ID")
		if requestID == "" {
			requestID = uuid.NewString()
		}

		c.Set(string(contextkeys.RequestID), requestID)
		c.Header("X-Request-ID", requestID)
		c.Next()
	}
}

func corsMiddleware(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		allowed := false
		for _, candidate := range cfg.CORS.AllowedOrigins {
			if candidate == "*" || candidate == origin {
				allowed = true
				break
			}
		}
		if allowed && origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PATCH, PUT, DELETE, OPTIONS")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func (r *Router) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			response.Error(c, apperrors.ErrTokenInvalid())
			c.Abort()
			return
		}

		claims, err := r.tokenMgr.Verify(strings.TrimSpace(authHeader[7:]))
		if err != nil {
			response.Error(c, err)
			c.Abort()
			return
		}

		// Access tokens are stateless, so consult the Redis session record to
		// enforce immediate logout/session revocation.
		if r.redis != nil && claims.SessionID != "" {
			active, err := r.redis.Exists(c.Request.Context(), "session:"+claims.SessionID)
			if err != nil {
				response.Error(c, apperrors.ErrServiceUnavailable("session store unavailable"))
				c.Abort()
				return
			}
			if !active {
				response.Error(c, apperrors.ErrTokenInvalid())
				c.Abort()
				return
			}
		}

		c.Set(string(contextkeys.UserID), claims.Subject)
		c.Set(string(contextkeys.SessionID), claims.SessionID)
		c.Set(string(contextkeys.UserRoles), claims.Roles)
		c.Next()
	}
}

func notImplemented(c *gin.Context) {
	response.Error(c, apperrors.ErrNotImplemented())
}

// Ensure Router implements http.Handler.
var _ http.Handler = (*Router)(nil)
