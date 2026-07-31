//go:build !wireinject
// +build !wireinject

package main

import (
	"context"
	"fmt"

	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/admin"
	"github.com/MehulChamoli/auth-service/internal/api"
	"github.com/MehulChamoli/auth-service/internal/auth"
	"github.com/MehulChamoli/auth-service/internal/mfa"
	"github.com/MehulChamoli/auth-service/internal/oauth"
	"github.com/MehulChamoli/auth-service/internal/user"
	"github.com/MehulChamoli/auth-service/internal/worker"
	"github.com/MehulChamoli/auth-service/pkg/cache"
	"github.com/MehulChamoli/auth-service/pkg/database"
	pkggrpc "github.com/MehulChamoli/auth-service/pkg/grpc"
	"github.com/MehulChamoli/auth-service/pkg/metrics"
	"github.com/MehulChamoli/auth-service/pkg/token"
)

// App aggregates the top-level server components.
type App struct {
	Router     *api.Router
	GRPCServer *pkggrpc.Server
	Workers    *worker.Manager
}

// InitializeApp constructs the service graph without requiring wire generation.
func InitializeApp(cfg *config.Config) (*App, func(), error) {
	ctx := context.Background()

	pool, err := database.NewPool(ctx, &cfg.Database)
	if err != nil {
		return nil, nil, fmt.Errorf("initializing database: %w", err)
	}

	redisClient, err := cache.NewRedisClient(&cfg.Redis)
	if err != nil {
		pool.Close()
		return nil, nil, fmt.Errorf("initializing redis: %w", err)
	}

	tokenManager, err := token.NewManager(&cfg.JWT)
	if err != nil {
		_ = redisClient.Close()
		pool.Close()
		return nil, nil, err
	}

	userRepo := user.NewRepository(pool)
	userSvc := user.NewService(userRepo)
	userHandler := user.NewHandler(userSvc)

	mfaRepo := mfa.NewRepository(pool)
	mfaSvc := mfa.NewService(mfaRepo, userRepo, &cfg.Security)
	mfaHandler := mfa.NewHandler(mfaSvc)

	adminRepo := admin.NewRepository(pool)
	adminSvc := admin.NewService(adminRepo)
	adminHandler := admin.NewHandler(adminSvc)

	authRepo := auth.NewRepository(pool)
	authSvc := auth.NewService(authRepo, userRepo, mfaSvc, redisClient, tokenManager, &cfg.Security, cfg.App.Env)
	authHandler := auth.NewHandler(authSvc)
	oauthRepo := oauth.NewRepository(pool)
	oauthSvc := oauth.NewService(oauthRepo, userRepo, redisClient, tokenManager, cfg)
	oauthHandler := oauth.NewHandler(oauthSvc)

	collector, err := metrics.NewPrometheusCollector()
	if err != nil {
		_ = redisClient.Close()
		pool.Close()
		return nil, nil, fmt.Errorf("initializing metrics: %w", err)
	}

	app := &App{
		Router:     api.NewRouter(cfg, tokenManager, authHandler, userHandler, adminHandler, mfaHandler, oauthHandler, pool, redisClient, collector),
		GRPCServer: pkggrpc.NewServer(),
		Workers:    worker.NewManager(pool, nil),
	}

	cleanup := func() {
		app.Workers.Stop()
		_ = redisClient.Close()
		pool.Close()
	}

	return app, cleanup, nil
}
