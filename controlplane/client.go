package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/danthegoodman1/vbuckets/env"
	"github.com/maypok86/otter/v2"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

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

type controlPlaneDialConfig struct {
	SecurityMode  string
	TLSCAFile     string
	TLSServerName string
	TLSCertFile   string
	TLSKeyFile    string
	BearerToken   string
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
	cfg := controlPlaneDialConfigFromEnv()
	c.logger.Info().Str("url", c.url).Str("securityMode", normalizeSecurityMode(cfg.SecurityMode)).Msg("connecting to control plane")

	dialOptions, err := buildDialOptions(cfg)
	if err != nil {
		c.logger.Error().Err(err).Msg("invalid control plane connection configuration")
		return
	}

	conn, err := grpc.NewClient(c.url, dialOptions...)
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

func controlPlaneDialConfigFromEnv() controlPlaneDialConfig {
	return controlPlaneDialConfig{
		SecurityMode:  env.ControlPlaneSecurityMode,
		TLSCAFile:     env.ControlPlaneTLSCAFile,
		TLSServerName: env.ControlPlaneTLSServerName,
		TLSCertFile:   env.ControlPlaneTLSCertFile,
		TLSKeyFile:    env.ControlPlaneTLSKeyFile,
		BearerToken:   env.ControlPlaneAuthBearerToken,
	}
}

func normalizeSecurityMode(mode string) string {
	mode = strings.TrimSpace(strings.ToLower(mode))
	if mode == "" {
		return "insecure"
	}
	return mode
}

func buildDialOptions(cfg controlPlaneDialConfig) ([]grpc.DialOption, error) {
	transportCredentials, err := buildTransportCredentials(cfg)
	if err != nil {
		return nil, err
	}

	options := []grpc.DialOption{
		grpc.WithTransportCredentials(transportCredentials),
	}

	if token := strings.TrimSpace(cfg.BearerToken); token != "" {
		options = append(options,
			grpc.WithUnaryInterceptor(bearerAuthUnaryInterceptor(token)),
			grpc.WithStreamInterceptor(bearerAuthStreamInterceptor(token)),
		)
	}

	return options, nil
}

func buildTransportCredentials(cfg controlPlaneDialConfig) (credentials.TransportCredentials, error) {
	switch normalizeSecurityMode(cfg.SecurityMode) {
	case "insecure":
		return insecure.NewCredentials(), nil

	case "tls", "mtls":
		tlsConfig := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		if cfg.TLSServerName != "" {
			tlsConfig.ServerName = cfg.TLSServerName
		}

		if cfg.TLSCAFile != "" {
			caPEM, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("read control plane CA file: %w", err)
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(caPEM) {
				return nil, fmt.Errorf("parse control plane CA file: no valid certificates found")
			}
			tlsConfig.RootCAs = roots
		}

		if normalizeSecurityMode(cfg.SecurityMode) == "mtls" {
			if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
				return nil, fmt.Errorf("CONTROL_PLANE_TLS_CERT_FILE and CONTROL_PLANE_TLS_KEY_FILE are required for mtls mode")
			}
			certificate, err := tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load control plane client certificate: %w", err)
			}
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}

		return credentials.NewTLS(tlsConfig), nil

	default:
		return nil, fmt.Errorf("unsupported CONTROL_PLANE_SECURITY_MODE %q", cfg.SecurityMode)
	}
}

func bearerAuthUnaryInterceptor(token string) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req any, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		return invoker(withBearerToken(ctx, token), method, req, reply, cc, opts...)
	}
}

func bearerAuthStreamInterceptor(token string) grpc.StreamClientInterceptor {
	return func(ctx context.Context, desc *grpc.StreamDesc, cc *grpc.ClientConn, method string, streamer grpc.Streamer, opts ...grpc.CallOption) (grpc.ClientStream, error) {
		return streamer(withBearerToken(ctx, token), desc, cc, method, opts...)
	}
}

func withBearerToken(ctx context.Context, token string) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

func (c *Client) handleDelta(delta *apiv1.Delta) {
	switch d := delta.Delta.(type) {
	case *apiv1.Delta_Credentials:
		cd := d.Credentials
		if cd.Remove {
			c.caches.credentials.Invalidate(cd.AccessKeyId)
			c.logger.Debug().Str("accessKeyID", cd.AccessKeyId).Msg("credential removed via delta")
		} else {
			policy, err := http_server.ParseS3IAMPolicyJSON(cd.IamPolicyJson)
			if err != nil {
				c.caches.credentials.Invalidate(cd.AccessKeyId)
				c.logger.Error().Err(err).Str("accessKeyID", cd.AccessKeyId).Msg("invalid credential IAM policy in delta")
				return
			}
			c.caches.credentials.Set(cd.AccessKeyId, cachedCredentials{
				VirtualCredentials: &http_server.VirtualCredentials{
					SecretKey: cd.SecretKey,
					IAMPolicy: policy,
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
		policy, err := http_server.ParseS3IAMPolicyJSON(resp.IamPolicyJson)
		if err != nil {
			return cachedCredentials{}, err
		}
		return cachedCredentials{
			VirtualCredentials: &http_server.VirtualCredentials{
				SecretKey: resp.SecretKey,
				IAMPolicy: policy,
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

func (c *Client) CreateVBucket(ctx context.Context, accessKeyID, bucketName, locationConstraint string) (*http_server.VBucketConfig, error) {
	client := c.getClient()
	if client == nil {
		return nil, errNotConnected
	}
	resp, err := client.CreateVBucket(ctx, &apiv1.CreateVBucketRequest{
		AccessKeyId:        accessKeyID,
		BucketName:         bucketName,
		LocationConstraint: locationConstraint,
	})
	if err != nil {
		return nil, mapCreateVBucketError(err)
	}

	cfg := &http_server.VBucketConfig{
		RealEndpoint:     resp.RealEndpoint,
		RealBucket:       resp.RealBucket,
		RealAccessKey:    resp.RealAccessKey,
		RealSecretKey:    resp.RealSecretKey,
		RealRegion:       resp.RealRegion,
		PathPrefix:       resp.PathPrefix,
		RealUsePathStyle: resp.RealUsePathStyle,
	}
	c.caches.vbuckets.Set(vbucketCacheKey(accessKeyID, bucketName), cachedVBucket{
		VBucketConfig: cfg,
		TTL:           resp.Ttl.AsDuration(),
	})
	return cfg, nil
}

func (c *Client) ListVBuckets(ctx context.Context, accessKeyID string) ([]http_server.ListedVBucket, error) {
	client := c.getClient()
	if client == nil {
		return nil, errNotConnected
	}
	resp, err := client.ListVBuckets(ctx, &apiv1.ListVBucketsRequest{
		AccessKeyId: accessKeyID,
	})
	if err != nil {
		return nil, mapListVBucketsError(err)
	}

	buckets := make([]http_server.ListedVBucket, 0, len(resp.Buckets))
	for _, bucket := range resp.Buckets {
		listed := http_server.ListedVBucket{Name: bucket.BucketName}
		if bucket.CreationDate != nil {
			listed.CreationDate = bucket.CreationDate.AsTime()
		}
		buckets = append(buckets, listed)
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
