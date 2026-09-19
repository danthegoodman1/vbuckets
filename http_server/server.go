package http_server

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
)

type RegisterRoutes func(r chi.Router)

type ReadinessSnapshot struct {
	Ready                bool      `json:"ready"`
	State                string    `json:"state"`
	Revision             uint64    `json:"revision"`
	CursorPresent        bool      `json:"cursor_present"`
	BarrierRequired      bool      `json:"barrier_required"`
	RequiredRevision     uint64    `json:"required_revision,omitempty"`
	LastGapRevision      uint64    `json:"last_gap_revision,omitempty"`
	LastTransitionUTC    time.Time `json:"last_transition_utc"`
	LastDisconnectReason string    `json:"last_disconnect_reason,omitempty"`
	Stats                any       `json:"stats,omitempty"`
}

type ReadinessProvider interface {
	ReadinessSnapshot() ReadinessSnapshot
}

// NewServer serves only S3 traffic. Health paths must not occupy object keys.
func NewServer(addr string, registerRoutes RegisterRoutes) *http.Server {
	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)
	if registerRoutes != nil {
		registerRoutes(r)
	}
	return newHTTPServer(addr, r)
}

func NewAdminServer(addr string, readiness ReadinessProvider) *http.Server {
	r := chi.NewRouter()
	r.Get("/hc", HealthCheck)
	r.Get("/ready", ReadinessCheck(readiness))
	return newHTTPServer(addr, r)
}

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: env.Current.HTTP.ReadHeaderTimeout,
		IdleTimeout:       env.Current.HTTP.IdleTimeout,
		ReadTimeout:       env.Current.HTTP.ReadTimeout,
		WriteTimeout:      env.Current.HTTP.WriteTimeout,
	}
}

func ReadinessCheck(readiness ReadinessProvider) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if readiness == nil {
			writeJSON(r.Context(), w, http.StatusOK, map[string]any{"status": "ready", "state": "standalone"})
			return
		}
		snapshot := readiness.ReadinessSnapshot()
		status := http.StatusServiceUnavailable
		if snapshot.Ready {
			status = http.StatusOK
		}
		writeJSON(r.Context(), w, status, snapshot)
	}
}

func HealthCheck(w http.ResponseWriter, r *http.Request) {
	writeJSON(r.Context(), w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	logger := zerolog.Ctx(ctx)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Error().Err(err).Msg("failed to encode JSON response")
	}
}
