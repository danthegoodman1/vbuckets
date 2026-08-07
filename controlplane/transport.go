package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/danthegoodman1/vbuckets/env"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type controlPlaneDialConfig struct {
	SecurityMode  string
	TLSCAFile     string
	TLSServerName string
	TLSCertFile   string
	TLSKeyFile    string
	BearerToken   string
}

func controlPlaneDialConfigFromEnv() controlPlaneDialConfig {
	return controlPlaneDialConfig{SecurityMode: env.ControlPlaneSecurityMode, TLSCAFile: env.ControlPlaneTLSCAFile, TLSServerName: env.ControlPlaneTLSServerName, TLSCertFile: env.ControlPlaneTLSCertFile, TLSKeyFile: env.ControlPlaneTLSKeyFile, BearerToken: env.ControlPlaneAuthBearerToken}
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
	options := []grpc.DialOption{grpc.WithTransportCredentials(transportCredentials)}
	if token := strings.TrimSpace(cfg.BearerToken); token != "" {
		options = append(options, grpc.WithUnaryInterceptor(bearerAuthUnaryInterceptor(token)), grpc.WithStreamInterceptor(bearerAuthStreamInterceptor(token)))
	}
	return options, nil
}

func buildTransportCredentials(cfg controlPlaneDialConfig) (credentials.TransportCredentials, error) {
	switch normalizeSecurityMode(cfg.SecurityMode) {
	case "insecure":
		return insecure.NewCredentials(), nil
	case "tls", "mtls":
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
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
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
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
