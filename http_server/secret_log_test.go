package http_server

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
)

func TestResolverFailureLogsDoNotExposeIdentifiersFromErrors(t *testing.T) {
	const sentinel = "AKIA-SENTINEL secret-bucket"
	resolver := newTestResolver()
	resolver.credentials = func(context.Context, string) (*VirtualCredentials, error) { return nil, errors.New(sentinel) }
	var output bytes.Buffer
	logger := zerolog.New(&output)
	handler := S3Auth(resolver)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected handler call") }))
	request := signedRequest(t, http.MethodGet, "http://s3.example.com/bucket/key", nil, unsignedPayload, validCreds)
	request = request.WithContext(logger.WithContext(request.Context()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.NotContains(t, output.String(), sentinel)
	require.Contains(t, output.String(), "credential lookup failed")
}

func TestMalformedAuthorizationLogsDoNotExposeCredentialMaterial(t *testing.T) {
	const sentinel = "AKIA-MALFORMED-SENTINEL"
	var output bytes.Buffer
	logger := zerolog.New(&output)
	handler := S3Auth(newTestResolver())(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unexpected handler call") }))
	request := httptest.NewRequest(http.MethodGet, "http://s3.example.com/bucket/key", nil)
	request.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+sentinel+"/broken, SignedHeaders=host;x-amz-date, Signature="+strings.Repeat("a", 64))
	request = request.WithContext(logger.WithContext(request.Context()))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	require.Equal(t, http.StatusBadRequest, recorder.Code)
	require.NotContains(t, output.String(), sentinel)
	require.Contains(t, output.String(), "failed to parse authorization header")
}
