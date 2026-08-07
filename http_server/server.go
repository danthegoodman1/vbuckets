package http_server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/rs/zerolog"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
)

type Server struct {
	server     *http.Server
	router     *chi.Mux
	grpcServer *grpc.Server
}

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

func NewServer(addr string, grpcServer *grpc.Server, registerRoutes RegisterRoutes) *Server {
	return NewServerWithReadiness(addr, grpcServer, registerRoutes, nil)
}

func NewServerWithReadiness(addr string, grpcServer *grpc.Server, registerRoutes RegisterRoutes, readiness ReadinessProvider) *Server {
	r := chi.NewRouter()

	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	r.Get("/hc", HealthCheck)
	r.Get("/ready", ReadinessCheck(readiness))

	if registerRoutes != nil {
		registerRoutes(r)
	}

	// Create a handler that routes gRPC requests to the gRPC server
	// and HTTP requests to the chi router
	var handler http.Handler
	if grpcServer != nil {
		handler = grpcHTTPMux(grpcServer, r)
	} else {
		handler = r
	}

	h2s := &http2.Server{}
	h2cHandler := h2c.NewHandler(handler, h2s)

	s := &Server{
		router:     r,
		grpcServer: grpcServer,
		server: &http.Server{
			Addr:              addr,
			Handler:           h2cHandler,
			ReadHeaderTimeout: env.HTTPReadHeaderTimeout,
			IdleTimeout:       env.HTTPIdleTimeout,
			ReadTimeout:       env.HTTPReadTimeout,
			WriteTimeout:      env.HTTPWriteTimeout,
			BaseContext: func(l net.Listener) context.Context {
				return context.Background()
			},
		},
	}

	return s
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

// grpcHTTPMux returns a handler that routes gRPC requests to the gRPC server
// and all other requests to the HTTP handler.
func grpcHTTPMux(grpcServer *grpc.Server, httpHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor == 2 && strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			httpHandler.ServeHTTP(w, r)
		}
	})
}

func (s *Server) Start() error {
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	return s.server.Shutdown(ctx)
}

func (s *Server) Addr() string {
	return s.server.Addr
}

func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	return s.server.Serve(listener)
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
