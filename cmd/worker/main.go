package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MehulChamoli/auth-service/internal/worker"
)

func main() {
	fmt.Println("worker service starting")
	// Pass nil db and nil dispatcher: NewManager uses LogDispatcher when
	// dispatcher is nil, and skips DB polling when db is nil.
	m := worker.NewManager(nil, nil)
	go m.Start()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	m.Stop()
	fmt.Println("worker service stopped")
}

