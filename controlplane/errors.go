package controlplane

import "errors"

var (
	errNotConnected           = errors.New("not connected to control plane")
	ErrUnsynchronized         = errors.New("control plane is not synchronized")
	ErrNotFound               = errors.New("control-plane object not found")
	ErrMissRejected           = errors.New("control-plane miss admission rejected")
	ErrRevisionRace           = errors.New("control-plane revision changed during lookup")
	ErrWatchSilence           = errors.New("control-plane watch heartbeat timed out")
	ErrSynchronizationTimeout = errors.New("control-plane synchronization timed out")
)
