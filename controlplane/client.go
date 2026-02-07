package controlplane

import (
	"context"
	"sync"
	"time"

	"github.com/maypok86/otter/v2"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/danthegoodman1/vbuckets/http_server"
	apiv1 "github.com/danthegoodman1/vbuckets/v1"
)

type Client struct {
	url    string
	logger zerolog.Logger
	caches *caches

	mu     sync.RWMutex
	conn   *grpc.ClientConn
	client apiv1.ControlPlaneClient
}

func NewClient(url string, logger zerolog.Logger) *Client {
	return &Client{
		url:    url,
		logger: logger.With().Str("component", "controlplane").Logger(),
		caches: newCaches(),
	}
}

// Run maintains the connection to the control plane and listens for deltas.
// It reconnects automatically on failure with a backoff.
func (c *Client) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			c.connect(ctx)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

func (c *Client) connect(ctx context.Context) {
	c.logger.Info().Str("url", c.url).Msg("connecting to control plane")

	conn, err := grpc.NewClient(c.url, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to create grpc client")
		return
	}
	defer func() {
		conn.Close()
		c.mu.Lock()
		c.conn = nil
		c.client = nil
		c.mu.Unlock()
	}()

	client := apiv1.NewControlPlaneClient(conn)

	c.mu.Lock()
	c.conn = conn
	c.client = client
	c.mu.Unlock()

	c.logger.Info().Msg("connected to control plane")

	stream, err := client.ListenForDeltas(ctx, &apiv1.ListenForDeltasRequest{})
	if err != nil {
		c.logger.Error().Err(err).Msg("failed to open delta stream")
		return
	}

	for {
		delta, err := stream.Recv()
		if err != nil {
			c.logger.Error().Err(err).Msg("delta stream error")
			return
		}
		c.handleDelta(delta)
	}
}

func (c *Client) handleDelta(delta *apiv1.Delta) {
	switch d := delta.Delta.(type) {
	case *apiv1.Delta_Credentials:
		cd := d.Credentials
		if cd.Remove {
			c.caches.credentials.Invalidate(cd.AccessKeyId)
			c.logger.Debug().Str("accessKeyID", cd.AccessKeyId).Msg("credential removed via delta")
		} else {
			c.caches.credentials.Set(cd.AccessKeyId, cachedCredentials{
				VirtualCredentials: &http_server.VirtualCredentials{
					SecretKey: cd.SecretKey,
				},
				TTL: cd.Ttl.AsDuration(),
			})
			c.logger.Debug().Str("accessKeyID", cd.AccessKeyId).Msg("credential upserted via delta")
		}

	case *apiv1.Delta_BaseHost:
		bh := d.BaseHost
		if bh.Remove {
			c.caches.baseHosts.Invalidate(bh.Hostname)
			c.logger.Debug().Str("hostname", bh.Hostname).Msg("base host removed via delta")
		} else {
			c.caches.baseHosts.Set(bh.Hostname, cachedBaseHost{
				BaseHost: bh.BaseHost,
				Found:    bh.Found,
				TTL:      bh.Ttl.AsDuration(),
			})
			c.logger.Debug().Str("hostname", bh.Hostname).Msg("base host upserted via delta")
		}

	case *apiv1.Delta_Vbucket:
		vb := d.Vbucket
		key := vbucketCacheKey(vb.AccessKeyId, vb.BucketName)
		if vb.Remove {
			c.caches.vbuckets.Invalidate(key)
			c.logger.Debug().Str("key", key).Msg("vbucket removed via delta")
		} else {
			c.caches.vbuckets.Set(key, cachedVBucket{
				VBucketConfig: &http_server.VBucketConfig{
					RealEndpoint:     vb.RealEndpoint,
					RealBucket:       vb.RealBucket,
					RealAccessKey:    vb.RealAccessKey,
					RealSecretKey:    vb.RealSecretKey,
					RealRegion:       vb.RealRegion,
					PathPrefix:       vb.PathPrefix,
					RealUsePathStyle: vb.RealUsePathStyle,
				},
				TTL: vb.Ttl.AsDuration(),
			})
			c.logger.Debug().Str("key", key).Msg("vbucket upserted via delta")
		}

	default:
		c.logger.Warn().Msg("received unknown delta type")
	}
}

func (c *Client) getClient() apiv1.ControlPlaneClient {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.client
}

func (c *Client) LookupCredentials(ctx context.Context, accessKeyID string) (*http_server.VirtualCredentials, error) {
	loader := otter.LoaderFunc[string, cachedCredentials](func(ctx context.Context, key string) (cachedCredentials, error) {
		client := c.getClient()
		if client == nil {
			return cachedCredentials{}, errNotConnected
		}
		resp, err := client.LookupCredentials(ctx, &apiv1.LookupCredentialsRequest{
			AccessKeyId: key,
		})
		if err != nil {
			return cachedCredentials{}, err
		}
		return cachedCredentials{
			VirtualCredentials: &http_server.VirtualCredentials{
				SecretKey: resp.SecretKey,
			},
			TTL: resp.Ttl.AsDuration(),
		}, nil
	})

	result, err := c.caches.credentials.Get(ctx, accessKeyID, loader)
	if err != nil {
		return nil, err
	}
	return result.VirtualCredentials, nil
}

func (c *Client) LookupBaseHost(ctx context.Context, hostname string) (string, bool, error) {
	loader := otter.LoaderFunc[string, cachedBaseHost](func(ctx context.Context, key string) (cachedBaseHost, error) {
		client := c.getClient()
		if client == nil {
			return cachedBaseHost{}, errNotConnected
		}
		resp, err := client.LookupBaseHost(ctx, &apiv1.LookupBaseHostRequest{
			Hostname: key,
		})
		if err != nil {
			return cachedBaseHost{}, err
		}
		return cachedBaseHost{
			BaseHost: resp.BaseHost,
			Found:    resp.Found,
			TTL:      resp.Ttl.AsDuration(),
		}, nil
	})

	result, err := c.caches.baseHosts.Get(ctx, hostname, loader)
	if err != nil {
		return "", false, err
	}
	return result.BaseHost, result.Found, nil
}

func (c *Client) LookupVBucket(ctx context.Context, accessKeyID, bucketName string) (*http_server.VBucketConfig, error) {
	key := vbucketCacheKey(accessKeyID, bucketName)

	loader := otter.LoaderFunc[string, cachedVBucket](func(ctx context.Context, key string) (cachedVBucket, error) {
		client := c.getClient()
		if client == nil {
			return cachedVBucket{}, errNotConnected
		}
		resp, err := client.LookupVBucket(ctx, &apiv1.LookupVBucketRequest{
			AccessKeyId: accessKeyID,
			BucketName:  bucketName,
		})
		if err != nil {
			return cachedVBucket{}, err
		}
		return cachedVBucket{
			VBucketConfig: &http_server.VBucketConfig{
				RealEndpoint:     resp.RealEndpoint,
				RealBucket:       resp.RealBucket,
				RealAccessKey:    resp.RealAccessKey,
				RealSecretKey:    resp.RealSecretKey,
				RealRegion:       resp.RealRegion,
				PathPrefix:       resp.PathPrefix,
				RealUsePathStyle: resp.RealUsePathStyle,
			},
			TTL: resp.Ttl.AsDuration(),
		}, nil
	})

	result, err := c.caches.vbuckets.Get(ctx, key, loader)
	if err != nil {
		return nil, err
	}
	return result.VBucketConfig, nil
}
