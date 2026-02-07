package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/danthegoodman1/vbuckets/controlplane"
	"github.com/danthegoodman1/vbuckets/env"
	"github.com/danthegoodman1/vbuckets/gologger"
	"github.com/danthegoodman1/vbuckets/http_server"
)

var logger = gologger.NewLogger()

func main() {
	logger.Info().Msg("Starting vbuckets server")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if env.ControlPlaneURL == "" {
		logger.Fatal().Msg("CONTROL_PLANE_URL is required")
	}

	cpClient := controlplane.NewClient(env.ControlPlaneURL, logger)
	go cpClient.Run(ctx)
	logger.Info().Str("url", env.ControlPlaneURL).Msg("control plane client configured")

	server := http_server.NewServer(env.HTTPListenAddress, nil, http_server.RegisterS3Routes(cpClient))

	go func() {
		logger.Info().Str("addr", server.Addr()).Msg("starting HTTP server")
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	<-ctx.Done()

	logger.Info().Msg("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error().Err(err).Msg("error shutting down HTTP server")
	}

	logger.Info().Msg("shutdown complete")
}
