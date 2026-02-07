package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/danthegoodman1/vbuckets/gologger"
	"github.com/danthegoodman1/vbuckets/http_server"
)

var logger = gologger.NewLogger()

func main() {
	logger.Info().Msg("Starting vbuckets server")

	server := http_server.NewServer(":8080", nil, nil)

	go func() {
		logger.Info().Str("addr", server.Addr()).Msg("starting HTTP server")
		if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatal().Err(err).Msg("HTTP server error")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		logger.Error().Err(err).Msg("error shutting down HTTP server")
	}

	logger.Info().Msg("shutdown complete")
}
