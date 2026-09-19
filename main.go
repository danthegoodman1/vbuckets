package main

import (
	"context"
	"errors"
	"net/http"
	"os/signal"
	"sync"
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

	if env.LoadError != nil {
		logger.Fatal().Err(env.LoadError).Msg("invalid startup configuration")
	}
	if err := controlplane.ValidateTransportConfig(); err != nil {
		logger.Fatal().Err(err).Msg("invalid control-plane transport configuration")
	}

	cpClient := controlplane.NewClient(env.Current.ControlPlane.URL, logger)
	go cpClient.Run(ctx)
	logger.Info().Str("url", env.Current.ControlPlane.URL).Msg("control plane client configured")

	servers := []*http.Server{
		http_server.NewServer(env.Current.HTTP.Address, http_server.RegisterS3Routes(cpClient)),
		http_server.NewAdminServer(env.Current.HTTP.AdminAddress, cpClient),
	}
	for _, server := range servers {
		go func() {
			logger.Info().Str("addr", server.Addr).Msg("starting HTTP listener")
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Fatal().Err(err).Msg("HTTP server error")
			}
		}()
	}

	<-ctx.Done()

	logger.Info().Msg("shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var shutdown sync.WaitGroup
	for _, server := range servers {
		shutdown.Go(func() {
			if err := server.Shutdown(shutdownCtx); err != nil {
				logger.Error().Err(err).Msg("error shutting down HTTP listener")
				_ = server.Close()
			}
		})
	}
	shutdown.Wait()

	logger.Info().Msg("shutdown complete")
}
