//go:build wireinject
// +build wireinject

// Package main — Wire dependency injection declarations.
// Run `make wire` (or `wire gen ./cmd/server/`) to regenerate wire_gen.go.
// Wire validates the full dependency graph at compile time.
package main

import (
	"context"

	"github.com/google/wire"
	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/admin"
	"github.com/MehulChamoli/auth-service/internal/api"
	"github.com/MehulChamoli/auth-service/internal/auth"
	"github.com/MehulChamoli/auth-service/internal/mfa"
	"github.com/MehulChamoli/auth-service/internal/oauth"
	"github.com/MehulChamoli/auth-service/internal/rbac"
	"github.com/MehulChamoli/auth-service/internal/session"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/internal/webhook"
	"github.com/MehulChamoli/auth-service/internal/worker"
	"github.com/MehulChamoli/auth-service/pkg/cache"
	"github.com/MehulChamoli/auth-service/pkg/database"
	pkggrpc "github.com/MehulChamoli/auth-service/pkg/grpc"
	"github.com/MehulChamoli/auth-service/pkg/metrics"
	"github.com/MehulChamoli/auth-service/pkg/secrets"
	"github.com/MehulChamoli/auth-service/pkg/token"
	"github.com/MehulChamoli/auth-service/pkg/tracing"
)

// App aggregates the top-level server components.
type App struct {
	Router     *api.Router
	GRPCServer *pkggrpc.Server
	Workers    *worker.Manager
}

// ── Provider sets ──────────────────────────────────────────────────────────────

var ConfigSet = wire.NewSet(
	provideDatabaseConfig,
	provideRedisConfig,
	provideJWTConfig,
	provideSecurityConfig,
	provideSecretsConfig,
	provideOTELConfig,
)

// InfraSet wires infrastructure dependencies (DB, cache, tracing, metrics).
var InfraSet = wire.NewSet(
	database.NewPool,
	cache.NewRedisClient,
	cache.NewDistributedLock,
	secrets.NewProvider,
	tracing.NewTracerProvider,
	metrics.NewPrometheusCollector,
)

// TokenSet wires JWT signing/verification.
var TokenSet = wire.NewSet(
	token.NewManager,
)

// AuthSet wires the auth domain.
var AuthSet = wire.NewSet(
	auth.NewRepository,
	auth.NewService,
	auth.NewHandler,
)

// UserSet wires the user domain.
var UserSet = wire.NewSet(
	user.NewRepository,
	user.NewService,
	user.NewHandler,
)

// SessionSet wires session management.
var SessionSet = wire.NewSet(
	session.NewRedisStore,
	session.NewPGStore,
	session.NewService,
	session.NewHandler,
)

// RBACSet wires role-based access control.
var RBACSet = wire.NewSet(
	rbac.NewRepository,
	rbac.NewService,
	rbac.NewHandler,
)

// MFASet wires multi-factor authentication.
var MFASet = wire.NewSet(
	mfa.NewRepository,
	mfa.NewService,
	mfa.NewHandler,
)

// OAuthSet wires OAuth2 providers.
var OAuthSet = wire.NewSet(
	oauth.NewRepository,
	oauth.NewService,
	oauth.NewHandler,
)

// AdminSet wires admin dashboard APIs.
var AdminSet = wire.NewSet(
	admin.NewRepository,
	admin.NewService,
	admin.NewHandler,
)

// WebhookSet wires webhook dispatch.
var WebhookSet = wire.NewSet(
	webhook.NewRepository,
	webhook.NewDispatcher,
)

// WorkerSet wires background workers.
var WorkerSet = wire.NewSet(
	worker.NewManager,
)

// InitializeApp is the Wire injector function.
// Wire replaces this function body with generated code in wire_gen.go.
func InitializeApp(cfg *config.Config) (*App, func(), error) {
	wire.Build(
		provideContext,
		ConfigSet,
		InfraSet,
		TokenSet,
		AuthSet,
		UserSet,
		SessionSet,
		RBACSet,
		MFASet,
		OAuthSet,
		AdminSet,
		WebhookSet,
		WorkerSet,
		api.NewRouter,
		pkggrpc.NewServer,
		wire.Struct(new(App), "*"),
	)
	return nil, nil, nil
}

func provideContext() context.Context {
	return context.Background()
}

func provideDatabaseConfig(cfg *config.Config) *config.DatabaseConfig { return &cfg.Database }

func provideRedisConfig(cfg *config.Config) *config.RedisConfig { return &cfg.Redis }

func provideJWTConfig(cfg *config.Config) *config.JWTConfig { return &cfg.JWT }

func provideSecurityConfig(cfg *config.Config) *config.SecurityConfig { return &cfg.Security }

func provideSecretsConfig(cfg *config.Config) *config.SecretsConfig { return &cfg.Secrets }

func provideOTELConfig(cfg *config.Config) *config.OTELConfig { return &cfg.OTEL }
