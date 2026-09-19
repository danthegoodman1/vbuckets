package http_server

import (
	"context"
	"errors"
	"net/http"
)

var (
	ErrResolverNotFound        = errors.New("resolver object not found")
	ErrResolverUnavailable     = errors.New("resolver temporarily unavailable")
	ErrResolverThrottled       = errors.New("resolver admission rejected")
	ErrResolverInvalidResponse = errors.New("invalid resolver response")
)

func writeResolverError(w http.ResponseWriter, err error, credentials bool) {
	switch {
	case errors.Is(err, ErrResolverNotFound) && credentials:
		writeS3Error(w, http.StatusForbidden, "InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records.")
	case errors.Is(err, ErrResolverNotFound), errors.Is(err, ErrVBucketAccessDenied):
		writeS3Error(w, http.StatusForbidden, "AccessDenied", "Access Denied")
	case errors.Is(err, ErrResolverThrottled):
		writeS3Error(w, http.StatusServiceUnavailable, "SlowDown", "Please reduce your request rate.")
	case errors.Is(err, ErrResolverUnavailable), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		writeS3Error(w, http.StatusServiceUnavailable, "ServiceUnavailable", "Control plane is temporarily unavailable.")
	case errors.Is(err, ErrInvalidVBucketArgument):
		writeS3Error(w, http.StatusBadRequest, "InvalidRequest", "Invalid request.")
	default:
		writeS3Error(w, http.StatusBadGateway, "InternalError", "Invalid control-plane response.")
	}
}
