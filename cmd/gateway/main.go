package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/MeowMeowOrganization/meow-gateway/internal/bootstrap"
	"github.com/MeowMeowOrganization/meow-gateway/internal/config"
	"github.com/MeowMeowOrganization/meow-gateway/internal/logging"
)

func main() {
	os.Exit(run())
}

func run() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gateway configuration error: %v\n", err)
		return 1
	}

	logger := logging.New(cfg.Log, os.Stdout)
	app, err := bootstrap.New(cfg, logger)
	if err != nil {
		logger.Error("gateway bootstrap failed", "error", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := app.Run(ctx); err != nil {
		logger.Error("gateway exited with error", "error", err)
		return 1
	}
	return 0
}
