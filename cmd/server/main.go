// Package main is the entry point for the Auth Service.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/pkg/logger"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

var Version = "dev"

func main() {
	cfgPath := getEnv("CONFIG_PATH", "configs/app.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: loading config: %v\n", err)
		os.Exit(1)
	}

	l := logger.New(logger.Config{
		Level: getEnv("LOG_LEVEL", "info"), Pretty: cfg.IsDevelopment(),
		ServiceName: cfg.App.Name, ServiceVersion: Version,
	})
	l.Info().Str("env", cfg.App.Env).Int("http_port", cfg.App.Port).
		Int("grpc_port", cfg.App.GRPCPort).Msg("starting auth service")

	app, cleanup, err := InitializeApp(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialise application")
	}
	defer cleanup()

	grpcAddr := fmt.Sprintf(":%d", cfg.App.GRPCPort)
	grpcLn, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		log.Fatal().Err(err).Str("addr", grpcAddr).Msg("failed to listen on gRPC port")
	}
	errCh := make(chan error, 2)
	go func() {
		l.Info().Str("addr", grpcAddr).Msg("gRPC server listening")
		if err := app.GRPCServer.Serve(grpcLn); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			errCh <- fmt.Errorf("gRPC server: %w", err)
		}
	}()

	httpAddr := fmt.Sprintf(":%d", cfg.App.Port)
	httpServer := &http.Server{
		Addr: httpAddr, Handler: app.Router,
		ReadTimeout: 15 * time.Second, ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		l.Info().Str("addr", httpAddr).Msg("HTTP server listening")
		var serveErr error
		if cfg.TLS.Enabled {
			serveErr = httpServer.ListenAndServeTLS(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		} else {
			serveErr = httpServer.ListenAndServe()
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("HTTP server: %w", serveErr)
		}
	}()

	go app.Workers.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-quit:
		l.Info().Str("signal", sig.String()).Msg("shutdown signal received, draining connections...")
	case err := <-errCh:
		l.Error().Err(err).Msg("server error received, draining connections...")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.App.ShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		l.Error().Err(err).Msg("HTTP server forced shutdown")
	}

	grpcStopped := make(chan struct{})
	go func() {
		app.GRPCServer.GracefulStop()
		close(grpcStopped)
	}()
	select {
	case <-grpcStopped:
	case <-shutdownCtx.Done():
		l.Warn().Msg("gRPC graceful shutdown exceeded deadline; forcing stop")
		app.GRPCServer.Stop()
	}

	app.Workers.Stop()
	l.Info().Msg("auth service stopped cleanly")
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
