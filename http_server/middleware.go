package http_server

import (
	"context"
	"net/http"

	"github.com/google/uuid"
)

const RequestIDKey = "requestID"

func RequestID(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		requestID := uuid.Must(uuid.NewV7()).String()

		ctx = context.WithValue(ctx, RequestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
	return http.HandlerFunc(fn)
}
