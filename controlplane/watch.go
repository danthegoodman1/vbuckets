package controlplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"golang.org/x/net/publicsuffix"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"
)

func (c *Client) transitionLocked(state State) {
	if c.state == StateShutdown && state != StateShutdown {
		return
	}
	if c.state != state {
		transitioned := c.now()
		if c.state == StateReady && state != StateReady {
			c.epoch++
		}
		c.state = state
		c.lastTransition = transitioned.UTC()
		if state == StateSynchronizing {
			// Keep the raw time value so production clocks retain their
			// monotonic component. lastTransition is only for JSON status.
			c.synchronizingSince = transitioned
		}
		select {
		case c.stateChanged <- struct{}{}:
		default:
		}
	}
}

func (c *Client) requestResyncLocked() {
	if c.state == StateShutdown {
		return
	}
	c.barrierRequired = true
	c.transitionLocked(StateDisconnected)
	select {
	case c.resync <- struct{}{}:
	default:
	}
}

func (c *Client) markUnsynchronized(state State) {
	c.syncMu.Lock()
	c.transitionLocked(state)
	c.snapshot = nil
	c.barrierRequired = true
	c.syncMu.Unlock()
}

// Run maintains the revisioned watch. Any transport error or silent stream
// immediately removes readiness; jittered exponential backoff bounds reconnect
// pressure without synchronizing a fleet of proxies.
func (c *Client) Run(ctx context.Context) {
	backoff := c.opts.ReconnectMinBackoff
	for ctx.Err() == nil {
		c.markUnsynchronized(StateConnecting)
		synced, err := c.connect(ctx)
		if ctx.Err() != nil {
			break
		}
		c.metrics.watchReconnects.Add(1)
		if err != nil {
			c.logger.Error().Str("reason", disconnectReason(err)).Msg("control-plane watch disconnected")
		}
		if synced {
			backoff = c.opts.ReconnectMinBackoff
		}
		jitter := 0.5 + c.randFloat()
		delay := time.Duration(float64(backoff) * jitter)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
		backoff = minDuration(c.opts.ReconnectMaxBackoff, backoff*2)
	}
	c.markUnsynchronized(StateShutdown)
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func disconnectReason(err error) string {
	switch {
	case err == nil, errors.Is(err, io.EOF):
		return "watch_closed"
	case errors.Is(err, context.Canceled):
		return "shutdown"
	case errors.Is(err, ErrWatchSilence):
		return "watch_silence_timeout"
	case errors.Is(err, ErrSynchronizationTimeout):
		return "synchronization_timeout"
	case errors.Is(err, ErrRevisionRace):
		return "revision_resynchronization"
	default:
		return "watch_protocol_or_transport_error"
	}
}

func (c *Client) connect(ctx context.Context) (synced bool, returnErr error) {
	// Resync signals retire the stream that was current when they were emitted.
	// A prior stream can return through another select branch first, so discard
	// its stale signal before opening the replacement stream.
	select {
	case <-c.resync:
	default:
	}
	disconnected := false
	markDisconnected := func() {
		if disconnected {
			return
		}
		disconnected = true
		c.syncMu.Lock()
		c.lastDisconnectReason = disconnectReason(returnErr)
		c.transitionLocked(StateDisconnected)
		c.snapshot = nil
		c.barrierRequired = true
		c.syncMu.Unlock()
		if c.afterDisconnectState != nil {
			c.afterDisconnectState()
		}
	}
	defer markDisconnected()
	cfg := controlPlaneDialConfigFromEnv()
	dialOptions, err := buildDialOptions(cfg)
	if err != nil {
		return false, fmt.Errorf("control-plane connection configuration: %w", err)
	}
	conn, err := grpc.NewClient(c.url, dialOptions...)
	if err != nil {
		return false, fmt.Errorf("create grpc client: %w", err)
	}
	defer func() {
		// Fail readiness before making the transport unavailable. This closes
		// the teardown window in which status could claim Ready with no client.
		markDisconnected()
		_ = conn.Close()
		c.mu.Lock()
		if c.conn == conn {
			c.conn, c.client = nil, nil
		}
		c.mu.Unlock()
	}()
	client := apiv1.NewControlPlaneClient(conn)
	c.mu.Lock()
	c.conn, c.client = conn, client
	c.mu.Unlock()

	c.syncMu.Lock()
	c.transitionLocked(StateSynchronizing)
	request := &apiv1.WatchStateRequest{ResumeCursor: c.cursor, AfterRevision: c.revision}
	c.syncMu.Unlock()
	// Detach automatic parent cancellation so the select below can retire
	// readiness before this synchronization transport is canceled. Values are
	// preserved; only cancellation/deadline propagation is handled explicitly.
	watchCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer func() {
		// Readiness must fail before the stream cancellation can tear down the
		// synchronization transport.
		markDisconnected()
		cancel()
	}()
	stream, err := client.WatchState(watchCtx, request)
	if err != nil {
		return false, fmt.Errorf("open state watch: %w", err)
	}

	type recvResult struct {
		delta *apiv1.WatchEvent
		err   error
	}
	received := make(chan recvResult, 1)
	go func() {
		for {
			delta, recvErr := stream.Recv()
			select {
			case received <- recvResult{delta, recvErr}:
			case <-watchCtx.Done():
				return
			}
			if recvErr != nil {
				return
			}
		}
	}()
	silenceTimer := time.NewTimer(c.opts.WatchSilenceTimeout)
	defer silenceTimer.Stop()
	syncTimer := time.NewTimer(c.opts.SynchronizationTimeout)
	defer syncTimer.Stop()
	syncTimerC := syncTimer.C
	refreshSyncTimer := func() bool {
		c.syncMu.RLock()
		state, synchronizingSince := c.state, c.synchronizingSince
		c.syncMu.RUnlock()
		if state == StateReady {
			if syncTimerC != nil && !syncTimer.Stop() {
				select {
				case <-syncTimer.C:
				default:
				}
			}
			syncTimerC = nil
			return false
		}
		if state != StateSynchronizing {
			return false
		}
		remaining := c.opts.SynchronizationTimeout - c.now().Sub(synchronizingSince)
		if remaining <= 0 {
			return true
		}
		if syncTimerC != nil && !syncTimer.Stop() {
			select {
			case <-syncTimer.C:
			default:
			}
		}
		syncTimer.Reset(remaining)
		syncTimerC = syncTimer.C
		return false
	}
	for {
		select {
		case <-ctx.Done():
			return synced, ctx.Err()
		case <-c.stateChanged:
			if refreshSyncTimer() {
				return synced, ErrSynchronizationTimeout
			}
		case <-c.resync:
			return synced, ErrRevisionRace
		case <-silenceTimer.C:
			return synced, ErrWatchSilence
		case <-syncTimerC:
			return synced, ErrSynchronizationTimeout
		case result := <-received:
			if result.err != nil {
				if errors.Is(result.err, io.EOF) {
					return synced, io.EOF
				}
				return synced, result.err
			}
			if err := c.processWatch(result.delta); err != nil {
				return synced, err
			}
			if !silenceTimer.Stop() {
				select {
				case <-silenceTimer.C:
				default:
				}
			}
			silenceTimer.Reset(c.opts.WatchSilenceTimeout)
			if c.Ready() {
				synced = true
			}
			if refreshSyncTimer() {
				return synced, ErrSynchronizationTimeout
			}
		}
	}
}

func normalizeBaseDomain(value string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if domain == "" || len(domain) > 253 || strings.Contains(domain, ":") || strings.Contains(domain, "*") || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") || strings.Contains(domain, "..") || net.ParseIP(domain) != nil {
		return "", fmt.Errorf("invalid base domain")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid base domain")
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", fmt.Errorf("invalid base domain")
			}
		}
	}
	if _, err := publicsuffix.EffectiveTLDPlusOne(domain); err != nil {
		return "", fmt.Errorf("base domain must not be a public suffix: %w", err)
	}
	return domain, nil
}

func (c *Client) processWatch(delta *apiv1.WatchEvent) (err error) {
	if delta == nil || delta.Event == nil {
		return fmt.Errorf("empty watch event")
	}
	c.syncMu.Lock()
	defer func() {
		if err != nil {
			c.barrierRequired = true
			c.transitionLocked(StateDisconnected)
		}
		c.syncMu.Unlock()
	}()
	if c.state != StateReady && c.state != StateSynchronizing {
		return ErrUnsynchronized
	}

	switch delta.Event.(type) {
	case *apiv1.WatchEvent_SnapshotBegin:
		if c.snapshot != nil {
			return fmt.Errorf("nested snapshot begin")
		}
		if delta.Revision == 0 || delta.Cursor != "" || delta.Revision < c.revision {
			return fmt.Errorf("invalid snapshot begin")
		}
		c.transitionLocked(StateSynchronizing)
		c.barrierRequired = true
		c.caches.credentials.InvalidateAll()
		c.caches.vbuckets.InvalidateAll()
		expectedCursor := ""
		if delta.Revision == c.revision {
			expectedCursor = c.cursor
		}
		c.snapshot = &snapshotState{revision: delta.Revision, expectedCursor: expectedCursor, previousCursor: c.cursor, baseHosts: make(map[string]uint64)}
		return nil
	case *apiv1.WatchEvent_SynchronizationBarrier:
		if delta.Revision == 0 || delta.Cursor == "" {
			return fmt.Errorf("invalid synchronization barrier")
		}
		if c.snapshot != nil {
			if delta.Revision != c.snapshot.revision {
				return fmt.Errorf("snapshot barrier revision %d does not match cut %d", delta.Revision, c.snapshot.revision)
			}
			if c.snapshot.expectedCursor != "" && delta.Cursor != c.snapshot.expectedCursor {
				return fmt.Errorf("same-revision snapshot changed canonical cursor")
			}
			if c.snapshot.revision > c.revision && c.snapshot.previousCursor != "" && delta.Cursor == c.snapshot.previousCursor {
				return fmt.Errorf("newer snapshot reused an older revision cursor")
			}
			c.baseHosts = c.snapshot.baseHosts
			c.snapshot = nil
			c.revision, c.cursor = delta.Revision, delta.Cursor
			c.barrierRequired = false
			if c.requiredRevision != 0 && c.revision >= c.requiredRevision {
				c.requiredRevision = 0
			}
			if c.requiredRevision == 0 {
				c.transitionLocked(StateReady)
			} else {
				c.transitionLocked(StateSynchronizing)
			}
			return nil
		}
		if delta.Revision != c.revision || delta.Cursor != c.cursor {
			return fmt.Errorf("resume barrier does not match accepted revision/cursor")
		}
		c.barrierRequired = false
		if c.requiredRevision == 0 || c.revision >= c.requiredRevision {
			c.requiredRevision = 0
			c.transitionLocked(StateReady)
		} else {
			c.transitionLocked(StateSynchronizing)
		}
		return nil
	case *apiv1.WatchEvent_Heartbeat:
		if c.snapshot != nil || delta.Revision != c.revision || delta.Cursor == "" || delta.Cursor != c.cursor {
			return fmt.Errorf("heartbeat does not match accepted revision/cursor")
		}
		return nil
	}

	if c.snapshot != nil {
		if delta.Revision == 0 || delta.Revision > c.snapshot.revision || delta.Cursor != "" {
			return fmt.Errorf("invalid snapshot entry envelope")
		}
		base, ok := delta.Event.(*apiv1.WatchEvent_BaseHost)
		if !ok {
			return fmt.Errorf("credential/vbucket snapshot entries are forbidden")
		}
		domain, err := baseHostDeltaDomain(base.BaseHost)
		if err != nil {
			return err
		}
		if base.BaseHost.Remove {
			return fmt.Errorf("snapshot cannot contain base-domain removals")
		}
		if _, exists := c.snapshot.baseHosts[domain]; exists {
			return fmt.Errorf("snapshot contains duplicate base domain")
		}
		if len(c.snapshot.baseHosts) >= c.baseHostMax {
			return fmt.Errorf("base-domain snapshot exceeds configured bound")
		}
		c.snapshot.baseHosts[domain] = delta.Revision
		return nil
	}

	if c.revision == 0 || c.cursor == "" {
		return fmt.Errorf("watch mutation received before snapshot")
	}
	if delta.Revision <= c.revision {
		c.transitionLocked(StateDisconnected)
		return fmt.Errorf("duplicate or reordered watch mutation")
	}
	if delta.Revision != c.revision+1 || delta.Cursor == "" || delta.Cursor == c.cursor {
		c.metrics.watchGaps.Add(1)
		c.lastGap = delta.Revision
		c.transitionLocked(StateDisconnected)
		return fmt.Errorf("watch revision gap: current=%d received=%d", c.revision, delta.Revision)
	}
	if err := c.applyEntityLocked(delta); err != nil {
		c.transitionLocked(StateDisconnected)
		return err
	}
	c.revision, c.cursor = delta.Revision, delta.Cursor
	if c.requiredRevision != 0 && c.revision >= c.requiredRevision {
		c.requiredRevision = 0
		if !c.barrierRequired {
			c.transitionLocked(StateReady)
		}
	}
	return nil
}

func baseHostDeltaDomain(delta *apiv1.BaseHostDelta) (string, error) {
	if delta == nil {
		return "", fmt.Errorf("missing base host delta")
	}
	return normalizeBaseDomain(delta.BaseHost)
}

func (c *Client) applyEntityLocked(delta *apiv1.WatchEvent) error {
	switch d := delta.Event.(type) {
	case *apiv1.WatchEvent_Credentials:
		if d.Credentials == nil || d.Credentials.AccessKeyId == "" {
			return fmt.Errorf("invalid credential delta")
		}
		_, hot := c.caches.credentials.GetIfPresent(d.Credentials.AccessKeyId)
		if d.Credentials.Remove {
			ttl, err := cacheTTL("credential removal", d.Credentials.NegativeTtl)
			if err != nil {
				c.caches.credentials.Invalidate(d.Credentials.AccessKeyId)
				return err
			}
			if hot {
				c.caches.credentials.Set(d.Credentials.AccessKeyId, cachedCredentials{Found: false, Revision: delta.Revision, TTL: ttl}, ttl)
			}
			return nil
		}
		if d.Credentials.NegativeTtl != nil {
			return fmt.Errorf("credential invalidation must not include negative TTL")
		}
		if hot {
			c.caches.credentials.Invalidate(d.Credentials.AccessKeyId)
		}
		return nil
	case *apiv1.WatchEvent_BaseHost:
		domain, err := baseHostDeltaDomain(d.BaseHost)
		if err != nil {
			return err
		}
		if d.BaseHost.Remove {
			delete(c.baseHosts, domain)
		} else {
			if _, exists := c.baseHosts[domain]; !exists && len(c.baseHosts) >= c.baseHostMax {
				return fmt.Errorf("base-domain registry exceeds configured bound")
			}
			c.baseHosts[domain] = delta.Revision
		}
		return nil
	case *apiv1.WatchEvent_Vbucket:
		if d.Vbucket == nil || d.Vbucket.AccessKeyId == "" || d.Vbucket.BucketName == "" {
			return fmt.Errorf("invalid vbucket delta")
		}
		key := vbucketCacheKey(d.Vbucket.AccessKeyId, d.Vbucket.BucketName)
		_, hot := c.caches.vbuckets.GetIfPresent(key)
		if d.Vbucket.Remove {
			ttl, err := cacheTTL("vbucket removal", d.Vbucket.NegativeTtl)
			if err != nil {
				c.caches.vbuckets.Invalidate(key)
				return err
			}
			if hot {
				c.caches.vbuckets.Set(key, cachedVBucket{Found: false, Revision: delta.Revision, TTL: ttl}, ttl)
			}
			return nil
		}
		if d.Vbucket.NegativeTtl != nil {
			return fmt.Errorf("vbucket invalidation must not include negative TTL")
		}
		if hot {
			c.caches.vbuckets.Invalidate(key)
		}
		return nil
	default:
		return fmt.Errorf("unknown watch event")
	}
}

func cacheTTL(source string, ttl *durationpb.Duration) (time.Duration, error) {
	if ttl == nil {
		return 0, fmt.Errorf("%s TTL is required", source)
	}
	if err := ttl.CheckValid(); err != nil {
		return 0, fmt.Errorf("%s TTL is invalid: %w", source, err)
	}
	duration := ttl.AsDuration()
	if duration <= 0 {
		return 0, fmt.Errorf("%s TTL must be positive", source)
	}
	return duration, nil
}
