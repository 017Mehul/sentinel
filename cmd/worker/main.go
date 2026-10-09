package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MehulChamoli/auth-service/config"
	"github.com/MehulChamoli/auth-service/internal/worker"
	"github.com/MehulChamoli/auth-service/pkg/database"
)

func main() {
	cfgPath := os.Getenv("CONFIG_PATH")
	if cfgPath == "" { cfgPath = "configs/app.yaml" }
	cfg, err := config.Load(cfgPath)
	if err != nil { fmt.Fprintf(os.Stderr, "FATAL: loading config: %v\\n", err); os.Exit(1) }

	ctx := context.Background()
	pool, err := database.NewPool(ctx, &cfg.Database)
	if err != nil { fmt.Fprintf(os.Stderr, "FATAL: connecting to database: %v\\n", err); os.Exit(1) }
	defer pool.Close()

	dispatcher := worker.NewSMTPDispatcher(cfg.SMTP)
	m := worker.NewManager(pool, dispatcher)
	go m.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	m.Stop()
}
