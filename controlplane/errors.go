package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/danthegoodman1/vbuckets/http_server"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	errNotConnected           = fmt.Errorf("%w: not connected to control plane", http_server.ErrResolverUnavailable)
	ErrUnsynchronized         = fmt.Errorf("%w: control plane is not synchronized", http_server.ErrResolverUnavailable)
	ErrNotFound               = http_server.ErrResolverNotFound
	ErrMissRejected           = http_server.ErrResolverThrottled
	ErrRevisionRace           = fmt.Errorf("%w: control-plane revision changed during lookup", http_server.ErrResolverUnavailable)
	ErrWatchSilence           = errors.New("control-plane watch heartbeat timed out")
	ErrSynchronizationTimeout = errors.New("control-plane synchronization timed out")
)

// mapResolverError preserves causes for diagnostics while exposing a small,
// transport-independent error contract to the HTTP adapter.
func mapResolverError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{
		http_server.ErrResolverNotFound, http_server.ErrResolverUnavailable, http_server.ErrResolverThrottled, http_server.ErrResolverInvalidResponse,
		http_server.ErrVBucketAccessDenied, http_server.ErrVBucketAlreadyOwnedByYou, http_server.ErrVBucketAlreadyExists, http_server.ErrInvalidVBucketName, http_server.ErrInvalidVBucketArgument,
	} {
		if errors.Is(err, known) {
			return err
		}
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %w", http_server.ErrResolverUnavailable, err)
	}
	if _, ok := status.FromError(err); ok {
		category := http_server.ErrResolverUnavailable
		switch status.Code(err) {
		case codes.NotFound:
			category = http_server.ErrResolverNotFound
		case codes.PermissionDenied, codes.Unauthenticated:
			category = http_server.ErrVBucketAccessDenied
		case codes.ResourceExhausted:
			category = http_server.ErrResolverThrottled
		}
		return fmt.Errorf("%w: %w", category, err)
	}
	return fmt.Errorf("%w: %w", http_server.ErrResolverInvalidResponse, err)
}
