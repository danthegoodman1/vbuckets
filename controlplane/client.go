package controlplane

import (
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/danthegoodman1/vbuckets/env"
	"github.com/danthegoodman1/vbuckets/http_server"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
)

type State string

const (
	StateStartup       State = "startup"
	StateConnecting    State = "connecting"
	StateSynchronizing State = "synchronizing"
	StateReady         State = "ready"
	StateDisconnected  State = "disconnected"
	StateShutdown      State = "shutdown"
)

type ClientOptions struct {
	UnaryTimeout           time.Duration
	WatchSilenceTimeout    time.Duration
	SynchronizationTimeout time.Duration
	ReconnectMinBackoff    time.Duration
	ReconnectMaxBackoff    time.Duration
	CredentialMissRate     float64
	CredentialMissBurst    int
	CredentialMissInFlight int
	VBucketMissRate        float64
	VBucketMissBurst       int
	VBucketMissInFlight    int
}

func defaultClientOptions() ClientOptions {
	return ClientOptions{
		UnaryTimeout:           2 * time.Second,
		WatchSilenceTimeout:    10 * time.Second,
		SynchronizationTimeout: 30 * time.Second,
		ReconnectMinBackoff:    250 * time.Millisecond,
		ReconnectMaxBackoff:    30 * time.Second,
		CredentialMissRate:     100,
		CredentialMissBurst:    100,
		CredentialMissInFlight: 32,
		VBucketMissRate:        100,
		VBucketMissBurst:       100,
		VBucketMissInFlight:    32,
	}
}

type metricCounters struct {
	cacheHits             atomic.Uint64
	cacheMisses           atomic.Uint64
	negativeHits          atomic.Uint64
	evictions             atomic.Uint64
	loadCoalesced         atomic.Uint64
	rejectedMisses        atomic.Uint64
	rejectedVBucketMisses atomic.Uint64
	watchGaps             atomic.Uint64
	watchReconnects       atomic.Uint64
	rpcCalls              atomic.Uint64
	rpcFailures           atomic.Uint64
	rpcLatencyNanos       atomic.Uint64

	mu          sync.Mutex
	lastRPCCode string
}

type ClientStats struct {
	CacheHits                uint64        `json:"cache_hits"`
	CacheMisses              uint64        `json:"cache_misses"`
	NegativeHits             uint64        `json:"negative_hits"`
	Evictions                uint64        `json:"evictions"`
	LoadCoalesced            uint64        `json:"load_coalesced"`
	RejectedCredentialMisses uint64        `json:"rejected_credential_misses"`
	RejectedVBucketMisses    uint64        `json:"rejected_vbucket_misses"`
	WatchGaps                uint64        `json:"watch_gaps"`
	WatchReconnects          uint64        `json:"watch_reconnects"`
	RPCCalls                 uint64        `json:"rpc_calls"`
	RPCFailures              uint64        `json:"rpc_failures"`
	LastRPCLatency           time.Duration `json:"last_rpc_latency"`
	LastRPCCode              string        `json:"last_rpc_code"`
	CredentialEntries        int           `json:"credential_entries"`
	BaseHostEntries          int           `json:"base_host_entries"`
	VBucketEntries           int           `json:"vbucket_entries"`
}

type SyncStatus struct {
	State                State       `json:"state"`
	Ready                bool        `json:"ready"`
	Revision             uint64      `json:"revision"`
	CursorPresent        bool        `json:"cursor_present"`
	BarrierRequired      bool        `json:"barrier_required"`
	LastGapRevision      uint64      `json:"last_gap_revision,omitempty"`
	RequiredRevision     uint64      `json:"required_revision,omitempty"`
	LastTransitionUTC    time.Time   `json:"last_transition_utc"`
	LastDisconnectReason string      `json:"last_disconnect_reason,omitempty"`
	Stats                ClientStats `json:"stats"`
}

type snapshotState struct {
	revision       uint64
	expectedCursor string
	previousCursor string
	baseHosts      map[string]uint64
}

type Client struct {
	url    string
	logger zerolog.Logger
	opts   ClientOptions
	caches *caches

	mu     sync.RWMutex
	conn   *grpc.ClientConn
	client apiv1.ControlPlaneClient

	syncMu               sync.RWMutex
	state                State
	revision             uint64
	cursor               string
	epoch                uint64
	snapshot             *snapshotState
	lastGap              uint64
	requiredRevision     uint64
	lastTransition       time.Time
	synchronizingSince   time.Time
	baseHosts            map[string]uint64
	baseHostMax          int
	barrierRequired      bool
	lastDisconnectReason string

	credentialLoads      loadGroup[string, cachedCredentials]
	vbucketLoads         loadGroup[string, cachedVBucket]
	metrics              metricCounters
	credentialAdmission  missAdmission
	vbucketAdmission     missAdmission
	randFloat            func() float64
	now                  func() time.Time
	resync               chan struct{}
	afterCacheRead       func()
	afterListParse       func()
	afterDisconnectState func()
	stateChanged         chan struct{}
}

func NewClient(url string, logger zerolog.Logger) *Client {
	return NewClientWithOptions(url, logger, defaultClientOptions())
}

func NewClientWithOptions(url string, logger zerolog.Logger, opts ClientOptions) *Client {
	now := time.Now
	defaults := defaultClientOptions()
	if opts.UnaryTimeout <= 0 {
		opts.UnaryTimeout = defaults.UnaryTimeout
	}
	if opts.WatchSilenceTimeout <= 0 {
		opts.WatchSilenceTimeout = defaults.WatchSilenceTimeout
	}
	if opts.SynchronizationTimeout <= 0 {
		opts.SynchronizationTimeout = defaults.SynchronizationTimeout
	}
	if opts.ReconnectMinBackoff <= 0 {
		opts.ReconnectMinBackoff = defaults.ReconnectMinBackoff
	}
	if opts.ReconnectMaxBackoff <= 0 {
		opts.ReconnectMaxBackoff = defaults.ReconnectMaxBackoff
	}
	if opts.ReconnectMaxBackoff < opts.ReconnectMinBackoff {
		opts.ReconnectMaxBackoff = opts.ReconnectMinBackoff
	}
	if opts.CredentialMissRate <= 0 {
		opts.CredentialMissRate = defaults.CredentialMissRate
	}
	if opts.CredentialMissBurst <= 0 {
		opts.CredentialMissBurst = defaults.CredentialMissBurst
	}
	if opts.CredentialMissInFlight <= 0 {
		opts.CredentialMissInFlight = defaults.CredentialMissInFlight
	}
	if opts.VBucketMissRate <= 0 {
		opts.VBucketMissRate = defaults.VBucketMissRate
	}
	if opts.VBucketMissBurst <= 0 {
		opts.VBucketMissBurst = defaults.VBucketMissBurst
	}
	if opts.VBucketMissInFlight <= 0 {
		opts.VBucketMissInFlight = defaults.VBucketMissInFlight
	}
	c := &Client{
		url: url, logger: logger.With().Str("component", "controlplane").Logger(), opts: opts,
		state: StateStartup, lastTransition: now().UTC(), randFloat: rand.Float64, now: now,
		baseHosts: make(map[string]uint64), baseHostMax: env.Current.Cache.MaxBaseHosts,
		barrierRequired: true,
		resync:          make(chan struct{}, 1),
		stateChanged:    make(chan struct{}, 1),
	}
	c.caches = newCaches(func() { c.metrics.evictions.Add(1) }, func() time.Time { return c.now() })
	c.credentialAdmission = newMissAdmission(opts.CredentialMissRate, opts.CredentialMissBurst, opts.CredentialMissInFlight, c.now())
	c.vbucketAdmission = newMissAdmission(opts.VBucketMissRate, opts.VBucketMissBurst, opts.VBucketMissInFlight, c.now())
	return c
}

func (c *Client) Ready() bool {
	c.syncMu.RLock()
	defer c.syncMu.RUnlock()
	return c.state == StateReady
}

func (c *Client) ReadinessSnapshot() http_server.ReadinessSnapshot {
	status := c.Status()
	return http_server.ReadinessSnapshot{Ready: status.Ready, State: string(status.State), Revision: status.Revision, CursorPresent: status.CursorPresent, BarrierRequired: status.BarrierRequired, RequiredRevision: status.RequiredRevision, LastGapRevision: status.LastGapRevision, LastTransitionUTC: status.LastTransitionUTC, LastDisconnectReason: status.LastDisconnectReason, Stats: status.Stats}
}

func (c *Client) Status() SyncStatus {
	c.syncMu.RLock()
	status := SyncStatus{State: c.state, Ready: c.state == StateReady, Revision: c.revision, CursorPresent: c.cursor != "", BarrierRequired: c.barrierRequired, LastGapRevision: c.lastGap, RequiredRevision: c.requiredRevision, LastTransitionUTC: c.lastTransition, LastDisconnectReason: c.lastDisconnectReason}
	c.syncMu.RUnlock()
	status.Stats = c.Stats()
	return status
}

func (c *Client) Stats() ClientStats {
	c.metrics.mu.Lock()
	lastCode := c.metrics.lastRPCCode
	c.metrics.mu.Unlock()
	return ClientStats{
		CacheHits: c.metrics.cacheHits.Load(), CacheMisses: c.metrics.cacheMisses.Load(), NegativeHits: c.metrics.negativeHits.Load(),
		Evictions: c.metrics.evictions.Load(), LoadCoalesced: c.metrics.loadCoalesced.Load(), RejectedCredentialMisses: c.metrics.rejectedMisses.Load(), RejectedVBucketMisses: c.metrics.rejectedVBucketMisses.Load(),
		WatchGaps: c.metrics.watchGaps.Load(), WatchReconnects: c.metrics.watchReconnects.Load(), RPCCalls: c.metrics.rpcCalls.Load(),
		RPCFailures: c.metrics.rpcFailures.Load(), LastRPCLatency: time.Duration(c.metrics.rpcLatencyNanos.Load()), LastRPCCode: lastCode,
		CredentialEntries: c.caches.credentials.Len(), BaseHostEntries: c.baseHostCount(), VBucketEntries: c.caches.vbuckets.Len(),
	}
}

func (c *Client) baseHostCount() int {
	c.syncMu.RLock()
	defer c.syncMu.RUnlock()
	return len(c.baseHosts)
}
