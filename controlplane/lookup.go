package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"github.com/danthegoodman1/vbuckets/http_server"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (c *Client) getClient() apiv1.ControlPlaneClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

func (c *Client) lookupSnapshot() (apiv1.ControlPlaneClient, uint64, uint64, error) {
	c.syncMu.RLock()
	defer c.syncMu.RUnlock()
	if c.state != StateReady {
		return nil, 0, 0, ErrUnsynchronized
	}
	client := c.getClient()
	if client == nil {
		return nil, 0, 0, errNotConnected
	}
	return client, c.revision, c.epoch, nil
}

func (c *Client) stillCurrent(revision, epoch uint64) bool {
	c.syncMu.RLock()
	defer c.syncMu.RUnlock()
	return c.state == StateReady && c.revision == revision && c.epoch == epoch
}

func (c *Client) BeginResolution() (http_server.ResolutionStamp, error) {
	_, revision, epoch, err := c.lookupSnapshot()
	return http_server.ResolutionStamp{Revision: revision, Epoch: epoch}, err
}

func (c *Client) ValidateResolution(stamp http_server.ResolutionStamp) error {
	if !c.stillCurrent(stamp.Revision, stamp.Epoch) {
		return ErrRevisionRace
	}
	return nil
}

func (c *Client) checkUnaryRevision(revision, expected uint64) error {
	if revision == expected {
		return nil
	}
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	if c.state == StateShutdown {
		return ErrRevisionRace
	}
	if revision < expected {
		c.requestResyncLocked()
	} else if revision > c.revision {
		c.requiredRevision = max(c.requiredRevision, revision)
		if c.state == StateReady {
			c.transitionLocked(StateSynchronizing)
		}
	}
	return ErrRevisionRace
}

func (c *Client) rpcContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, c.opts.UnaryTimeout)
}

func (c *Client) observeRPC(start time.Time, err error) {
	c.metrics.rpcCalls.Add(1)
	c.metrics.rpcLatencyNanos.Store(uint64(max(time.Duration(0), c.now().Sub(start))))
	code := status.Code(err).String()
	if err != nil {
		c.metrics.rpcFailures.Add(1)
	}
	c.metrics.mu.Lock()
	c.metrics.lastRPCCode = code
	c.metrics.mu.Unlock()
}

func (c *Client) LookupCredentials(ctx context.Context, accessKeyID string) (*http_server.VirtualCredentials, error) {
	value, err := c.lookupCredentials(ctx, accessKeyID, true)
	return value, mapResolverError(err)
}

func (c *Client) lookupCredentials(ctx context.Context, accessKeyID string, retry bool) (*http_server.VirtualCredentials, error) {
	client, revision, epoch, err := c.lookupSnapshot()
	if err != nil {
		if retry && errors.Is(err, ErrRevisionRace) && c.Ready() {
			return c.lookupCredentials(ctx, accessKeyID, false)
		}
		return nil, err
	}
	if cached, ok := c.caches.credentials.GetIfPresent(accessKeyID); ok && cached.Revision <= revision {
		c.metrics.cacheHits.Add(1)
		if c.afterCacheRead != nil {
			c.afterCacheRead()
		}
		if !c.stillCurrent(revision, epoch) {
			if retry && c.Ready() {
				return c.lookupCredentials(ctx, accessKeyID, false)
			}
			return nil, ErrRevisionRace
		}
		if !cached.Found {
			c.metrics.negativeHits.Add(1)
			return nil, ErrNotFound
		}
		clone := *cached.VirtualCredentials
		return &clone, nil
	}
	c.metrics.cacheMisses.Add(1)
	result, err, shared := c.credentialLoads.Do(ctx, accessKeyID, func() bool {
		if c.credentialAdmission.acquire(c.now()) {
			return true
		}
		c.metrics.rejectedMisses.Add(1)
		return false
	}, func() (cachedCredentials, error) {
		defer c.credentialAdmission.release()
		rpcCtx, cancel := c.rpcContext(context.WithoutCancel(ctx))
		defer cancel()
		start := c.now()
		resp, rpcErr := client.LookupCredentials(rpcCtx, &apiv1.LookupCredentialsRequest{AccessKeyId: accessKeyID, MinimumRevision: revision})
		c.observeRPC(start, rpcErr)
		if rpcErr != nil {
			return cachedCredentials{}, rpcErr
		}
		if resp == nil {
			return cachedCredentials{}, fmt.Errorf("missing credential lookup response")
		}
		if revisionErr := c.checkUnaryRevision(resp.Revision, revision); revisionErr != nil {
			return cachedCredentials{}, revisionErr
		}
		candidate, parseErr := credentialResponseEntry(resp)
		if parseErr != nil {
			return cachedCredentials{}, parseErr
		}
		c.syncMu.Lock()
		defer c.syncMu.Unlock()
		if c.state != StateReady || c.epoch != epoch {
			return cachedCredentials{}, ErrRevisionRace
		}
		if newer, ok := c.caches.credentials.GetIfPresent(accessKeyID); ok && newer.Revision > candidate.Revision && newer.Revision == c.revision {
			return newer, nil
		}
		if candidate.Revision > c.revision {
			c.requestResyncLocked()
			return cachedCredentials{}, ErrRevisionRace
		}
		if c.revision != revision || candidate.Revision != c.revision {
			return cachedCredentials{}, ErrRevisionRace
		}
		if newer, ok := c.caches.credentials.GetIfPresent(accessKeyID); ok && newer.Revision >= candidate.Revision {
			return newer, nil
		}
		c.caches.credentials.Set(accessKeyID, candidate, candidate.TTL)
		return candidate, nil
	})
	if shared {
		c.metrics.loadCoalesced.Add(1)
	}
	if err != nil {
		if retry && errors.Is(err, ErrRevisionRace) && c.Ready() {
			return c.lookupCredentials(ctx, accessKeyID, false)
		}
		return nil, err
	}
	if !c.stillCurrent(result.Revision, epoch) {
		if retry && c.Ready() {
			return c.lookupCredentials(ctx, accessKeyID, false)
		}
		return nil, ErrRevisionRace
	}
	if !result.Found {
		return nil, ErrNotFound
	}
	clone := *result.VirtualCredentials
	return &clone, nil
}

func credentialResponseEntry(resp *apiv1.LookupCredentialsResponse) (cachedCredentials, error) {
	if resp == nil || resp.Revision == 0 {
		return cachedCredentials{}, fmt.Errorf("invalid credential lookup revision")
	}
	if !resp.Found {
		if resp.SecretKey != "" || resp.IamPolicyJson != "" || resp.Ttl != nil {
			return cachedCredentials{}, fmt.Errorf("negative credential response contains positive fields")
		}
		ttl, err := cacheTTL("LookupCredentials negative response", resp.NegativeTtl)
		if err != nil {
			return cachedCredentials{}, err
		}
		return cachedCredentials{Found: false, Revision: resp.Revision, TTL: ttl}, nil
	}
	if resp.NegativeTtl != nil {
		return cachedCredentials{}, fmt.Errorf("found credential response contains negative TTL")
	}
	ttl, err := cacheTTL("LookupCredentials response", resp.Ttl)
	if err != nil {
		return cachedCredentials{}, err
	}
	policy, err := http_server.ParseS3IAMPolicyJSON(resp.IamPolicyJson)
	if err != nil {
		return cachedCredentials{}, err
	}
	if resp.SecretKey == "" {
		return cachedCredentials{}, fmt.Errorf("credential secret key is required")
	}
	return cachedCredentials{VirtualCredentials: &http_server.VirtualCredentials{SecretKey: resp.SecretKey, IAMPolicy: policy}, Found: true, Revision: resp.Revision, TTL: ttl}, nil
}

func (c *Client) LookupBaseHost(_ context.Context, hostname string) (string, bool, error) {
	c.syncMu.RLock()
	defer c.syncMu.RUnlock()
	if c.state != StateReady {
		return "", false, ErrUnsynchronized
	}
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(hostname), "."))
	if net.ParseIP(host) != nil {
		return "", false, nil
	}
	if len(host) == 0 || len(host) > 253 {
		return "", false, http_server.ErrInvalidVBucketArgument
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, http_server.ErrInvalidVBucketArgument
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return "", false, http_server.ErrInvalidVBucketArgument
			}
		}
	}
	best := ""
	// Probe one suffix per DNS label, longest first. Request-host cardinality
	// never changes the control-plane-owned bounded registry.
	labels := strings.Split(host, ".")
	for index := 0; index < len(labels); index++ {
		candidate := strings.Join(labels[index:], ".")
		if _, found := c.baseHosts[candidate]; found {
			best = candidate
			break
		}
	}
	if best == "" {
		c.metrics.cacheMisses.Add(1)
		return "", false, nil
	}
	c.metrics.cacheHits.Add(1)
	return best, true, nil
}

func (c *Client) LookupVBucket(ctx context.Context, accessKeyID, bucketName string) (*http_server.VBucketConfig, error) {
	value, err := c.lookupVBucket(ctx, accessKeyID, bucketName, true)
	return value, mapResolverError(err)
}

func (c *Client) lookupVBucket(ctx context.Context, accessKeyID, bucketName string, retry bool) (*http_server.VBucketConfig, error) {
	client, revision, epoch, err := c.lookupSnapshot()
	if err != nil {
		if retry && errors.Is(err, ErrRevisionRace) && c.Ready() {
			return c.lookupVBucket(ctx, accessKeyID, bucketName, false)
		}
		return nil, err
	}
	key := vbucketCacheKey(accessKeyID, bucketName)
	if cached, ok := c.caches.vbuckets.GetIfPresent(key); ok && cached.Revision <= revision {
		c.metrics.cacheHits.Add(1)
		clone := cached.VBucketConfig.Clone()
		if c.afterCacheRead != nil {
			c.afterCacheRead()
		}
		if !c.stillCurrent(revision, epoch) {
			if retry && c.Ready() {
				return c.lookupVBucket(ctx, accessKeyID, bucketName, false)
			}
			return nil, ErrRevisionRace
		}
		if !cached.Found {
			c.metrics.negativeHits.Add(1)
			return nil, ErrNotFound
		}
		return clone, nil
	}
	c.metrics.cacheMisses.Add(1)
	result, err, shared := c.vbucketLoads.Do(ctx, key, func() bool {
		if c.vbucketAdmission.acquire(c.now()) {
			return true
		}
		c.metrics.rejectedVBucketMisses.Add(1)
		return false
	}, func() (cachedVBucket, error) {
		defer c.vbucketAdmission.release()
		rpcCtx, cancel := c.rpcContext(context.WithoutCancel(ctx))
		defer cancel()
		start := c.now()
		resp, rpcErr := client.LookupVBucket(rpcCtx, &apiv1.LookupVBucketRequest{AccessKeyId: accessKeyID, BucketName: bucketName, MinimumRevision: revision})
		c.observeRPC(start, rpcErr)
		if rpcErr != nil {
			return cachedVBucket{}, rpcErr
		}
		if resp == nil {
			return cachedVBucket{}, fmt.Errorf("missing vbucket lookup response")
		}
		if revisionErr := c.checkUnaryRevision(resp.Revision, revision); revisionErr != nil {
			return cachedVBucket{}, revisionErr
		}
		candidate, parseErr := vbucketResponseEntry(resp)
		if parseErr != nil {
			return cachedVBucket{}, parseErr
		}
		c.syncMu.Lock()
		defer c.syncMu.Unlock()
		if c.state != StateReady || c.epoch != epoch {
			return cachedVBucket{}, ErrRevisionRace
		}
		if newer, ok := c.caches.vbuckets.GetIfPresent(key); ok && newer.Revision > candidate.Revision && newer.Revision == c.revision {
			return newer, nil
		}
		if candidate.Revision > c.revision {
			c.requestResyncLocked()
			return cachedVBucket{}, ErrRevisionRace
		}
		if c.revision != revision || candidate.Revision != c.revision {
			return cachedVBucket{}, ErrRevisionRace
		}
		if newer, ok := c.caches.vbuckets.GetIfPresent(key); ok && newer.Revision >= candidate.Revision {
			return newer, nil
		}
		c.caches.vbuckets.Set(key, candidate, candidate.TTL)
		return candidate, nil
	})
	if shared {
		c.metrics.loadCoalesced.Add(1)
	}
	if err != nil {
		if retry && errors.Is(err, ErrRevisionRace) && c.Ready() {
			return c.lookupVBucket(ctx, accessKeyID, bucketName, false)
		}
		return nil, err
	}
	if !c.stillCurrent(result.Revision, epoch) {
		if retry && c.Ready() {
			return c.lookupVBucket(ctx, accessKeyID, bucketName, false)
		}
		return nil, ErrRevisionRace
	}
	if !result.Found {
		return nil, ErrNotFound
	}
	return result.VBucketConfig.Clone(), nil
}

func vbucketResponseEntry(resp *apiv1.LookupVBucketResponse) (cachedVBucket, error) {
	if resp == nil || resp.Revision == 0 {
		return cachedVBucket{}, fmt.Errorf("invalid vbucket lookup revision")
	}
	if !resp.Found {
		if resp.RealEndpoint != "" || resp.RealBucket != "" || resp.RealAccessKey != "" || resp.RealSecretKey != "" || resp.RealRegion != "" || resp.PathPrefix != "" || resp.RealUsePathStyle || len(resp.RoutingTokenKey) != 0 || resp.Ttl != nil {
			return cachedVBucket{}, fmt.Errorf("negative vbucket response contains positive fields")
		}
		ttl, err := cacheTTL("LookupVBucket negative response", resp.NegativeTtl)
		if err != nil {
			return cachedVBucket{}, err
		}
		return cachedVBucket{Found: false, Revision: resp.Revision, TTL: ttl}, nil
	}
	if resp.NegativeTtl != nil {
		return cachedVBucket{}, fmt.Errorf("found vbucket response contains negative TTL")
	}
	ttl, err := cacheTTL("LookupVBucket response", resp.Ttl)
	if err != nil {
		return cachedVBucket{}, err
	}
	cfg, err := http_server.NormalizeVBucketConfig(&http_server.VBucketConfig{RealEndpoint: resp.RealEndpoint, RealBucket: resp.RealBucket, RealAccessKey: resp.RealAccessKey, RealSecretKey: resp.RealSecretKey, RealRegion: resp.RealRegion, PathPrefix: resp.PathPrefix, RealUsePathStyle: resp.RealUsePathStyle, RoutingTokenKey: resp.RoutingTokenKey})
	if err != nil {
		return cachedVBucket{}, fmt.Errorf("invalid LookupVBucket mapping: %w", err)
	}
	return cachedVBucket{VBucketConfig: cfg, Found: true, Revision: resp.Revision, TTL: ttl}, nil
}

func (c *Client) CreateVBucket(ctx context.Context, accessKeyID, bucketName, locationConstraint string) (err error) {
	defer func() { err = mapResolverError(err) }()
	client, revision, _, err := c.lookupSnapshot()
	if err != nil {
		return err
	}
	rpcCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	start := c.now()
	resp, rpcErr := client.CreateVBucket(rpcCtx, &apiv1.CreateVBucketRequest{AccessKeyId: accessKeyID, BucketName: bucketName, LocationConstraint: locationConstraint, MinimumRevision: revision})
	c.observeRPC(start, rpcErr)
	if rpcErr != nil {
		return mapCreateVBucketError(rpcErr)
	}
	c.syncMu.Lock()
	if resp == nil || resp.Revision == 0 || resp.Revision <= revision {
		c.requestResyncLocked()
		c.syncMu.Unlock()
		return ErrRevisionRace
	}
	// A valid revision confirms that the mutation committed. A concurrent
	// watch disconnect or shutdown may prevent immediate catch-up, but it must
	// not turn that confirmed success into an ambiguous client error.
	if c.state == StateShutdown {
		c.syncMu.Unlock()
		return nil
	}
	if resp.Revision > c.revision {
		c.requiredRevision = max(c.requiredRevision, resp.Revision)
		if c.state == StateReady || c.state == StateSynchronizing {
			c.transitionLocked(StateSynchronizing)
		}
	}
	c.syncMu.Unlock()
	return nil
}

func (c *Client) ListVBuckets(ctx context.Context, accessKeyID string) (buckets []http_server.ListedVBucket, err error) {
	defer func() { err = mapResolverError(err) }()
	client, revision, epoch, err := c.lookupSnapshot()
	if err != nil {
		return nil, err
	}
	rpcCtx, cancel := c.rpcContext(ctx)
	defer cancel()
	start := c.now()
	resp, rpcErr := client.ListVBuckets(rpcCtx, &apiv1.ListVBucketsRequest{AccessKeyId: accessKeyID, MinimumRevision: revision})
	c.observeRPC(start, rpcErr)
	if rpcErr != nil {
		return nil, mapListVBucketsError(rpcErr)
	}
	if resp == nil {
		c.syncMu.Lock()
		c.requestResyncLocked()
		c.syncMu.Unlock()
		return nil, ErrRevisionRace
	}
	if revisionErr := c.checkUnaryRevision(resp.Revision, revision); revisionErr != nil {
		return nil, revisionErr
	}
	if !c.stillCurrent(revision, epoch) {
		return nil, ErrRevisionRace
	}
	buckets = make([]http_server.ListedVBucket, 0, len(resp.Buckets))
	for _, bucket := range resp.Buckets {
		if bucket == nil || bucket.CreationDate == nil {
			return nil, fmt.Errorf("invalid ListVBuckets response: bucket summary and creation date are required")
		}
		if err := bucket.CreationDate.CheckValid(); err != nil {
			return nil, fmt.Errorf("invalid ListVBuckets creation date for %q: %w", bucket.BucketName, err)
		}
		buckets = append(buckets, http_server.ListedVBucket{Name: bucket.BucketName, CreationDate: bucket.CreationDate.AsTime()})
	}
	if c.afterListParse != nil {
		c.afterListParse()
	}
	if !c.stillCurrent(revision, epoch) {
		return nil, ErrRevisionRace
	}
	return buckets, nil
}

func mapCreateVBucketError(err error) error {
	switch status.Code(err) {
	case codes.AlreadyExists:
		return fmt.Errorf("%w: %v", http_server.ErrVBucketAlreadyOwnedByYou, err)
	case codes.Aborted, codes.FailedPrecondition:
		return fmt.Errorf("%w: %v", http_server.ErrVBucketAlreadyExists, err)
	case codes.InvalidArgument:
		return fmt.Errorf("%w: %v", http_server.ErrInvalidVBucketArgument, err)
	case codes.PermissionDenied, codes.Unauthenticated, codes.NotFound:
		return fmt.Errorf("%w: %v", http_server.ErrVBucketAccessDenied, err)
	default:
		return err
	}
}
func mapListVBucketsError(err error) error {
	switch status.Code(err) {
	case codes.PermissionDenied, codes.Unauthenticated, codes.NotFound:
		return fmt.Errorf("%w: %v", http_server.ErrVBucketAccessDenied, err)
	default:
		return err
	}
}
