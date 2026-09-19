package http_server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

type mutableReadiness struct {
	mu       sync.RWMutex
	snapshot ReadinessSnapshot
}

func (r *mutableReadiness) ReadinessSnapshot() ReadinessSnapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.snapshot
}

func (r *mutableReadiness) set(snapshot ReadinessSnapshot) {
	r.mu.Lock()
	r.snapshot = snapshot
	r.mu.Unlock()
}

func TestReadinessStatusAndBodyComeFromOneSnapshot(t *testing.T) {
	provider := &mutableReadiness{}
	handler := ReadinessCheck(provider)
	for iteration := 0; iteration < 100; iteration++ {
		provider.set(ReadinessSnapshot{Ready: iteration%2 == 0, State: map[bool]string{true: "ready", false: "disconnected"}[iteration%2 == 0], Revision: uint64(iteration)})
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
		var body ReadinessSnapshot
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
		require.Equal(t, body.Ready, body.State == "ready")
		require.Equal(t, body.Ready, recorder.Code == http.StatusOK)
	}

	provider.set(ReadinessSnapshot{Ready: true, State: "ready"})
	stop := make(chan struct{})
	var toggler sync.WaitGroup
	toggler.Add(1)
	go func() {
		defer toggler.Done()
		for revision := uint64(0); ; revision++ {
			select {
			case <-stop:
				return
			default:
			}
			ready := revision%2 == 0
			provider.set(ReadinessSnapshot{Ready: ready, State: map[bool]string{true: "ready", false: "disconnected"}[ready], Revision: revision, BarrierRequired: !ready})
		}
	}()
	for range 1_000 {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
		var body ReadinessSnapshot
		require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &body))
		require.Equal(t, body.Ready, body.State == "ready")
		require.Equal(t, body.Ready, recorder.Code == http.StatusOK)
		require.Equal(t, !body.Ready, body.BarrierRequired)
	}
	close(stop)
	toggler.Wait()
}
