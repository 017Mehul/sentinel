package database

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/MehulChamoli/auth-service/config"
)

// NewPool creates and validates a pgx connection pool with the given configuration.
func NewPool(ctx context.Context, cfg *config.DatabaseConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("parsing database DSN: %w", err)
	}

	if cfg.MaxOpenConns <= 0 || cfg.MaxOpenConns > math.MaxInt32 {
		return nil, fmt.Errorf("database.max_open_conns must be between 1 and %d", math.MaxInt32)
	}
	if cfg.MaxIdleConns < 0 || cfg.MaxIdleConns > cfg.MaxOpenConns || cfg.MaxIdleConns > math.MaxInt32 {
		return nil, fmt.Errorf("database.max_idle_conns must be between 0 and max_open_conns")
	}

	poolCfg.MaxConns = int32(cfg.MaxOpenConns)
	poolCfg.MinConns = int32(cfg.MaxIdleConns)
	poolCfg.MaxConnLifetime = cfg.ConnMaxLifetime
	poolCfg.MaxConnIdleTime = cfg.ConnMaxIdleTime
	poolCfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("creating pgx pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	return pool, nil
}

func HealthCheck(ctx context.Context, pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return pool.Ping(ctx)
}

func Stats(pool *pgxpool.Pool) pgxpool.Stat {
	return *pool.Stat()
}
