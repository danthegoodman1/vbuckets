package http_server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCopySource(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want copySource
	}{
		{
			name: "bucket key",
			raw:  "test-bucket/source.txt",
			want: copySource{Bucket: "test-bucket", Key: "source.txt"},
		},
		{
			name: "leading slash",
			raw:  "/test-bucket/source.txt",
			want: copySource{Bucket: "test-bucket", Key: "source.txt"},
		},
		{
			name: "encoded key",
			raw:  "test-bucket/dir%2Fsource%20one%25.txt",
			want: copySource{Bucket: "test-bucket", Key: "dir/source one%.txt"},
		},
		{
			name: "special chars",
			raw:  "test-bucket/space%20and%2Bplus%3Fmark.txt",
			want: copySource{Bucket: "test-bucket", Key: "space and+plus?mark.txt"},
		},
		{
			name: "version id",
			raw:  "test-bucket/source.txt?versionId=v%2F1",
			want: copySource{Bucket: "test-bucket", Key: "source.txt", VersionID: "v/1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCopySource(tt.raw, "test-bucket")
			require.NoError(t, err)
			assert.Equal(t, tt.want, *got)
		})
	}
}

func TestParseCopySourceRejectsUnsupportedForms(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "empty", raw: ""},
		{name: "missing key", raw: "test-bucket"},
		{name: "empty key", raw: "test-bucket/"},
		{name: "wrong bucket", raw: "other-bucket/source.txt"},
		{name: "absolute url", raw: "https://s3.example.com/test-bucket/source.txt"},
		{name: "arn", raw: "arn:aws:s3:::test-bucket/source.txt"},
		{name: "access point like arn path", raw: "/arn:aws:s3:us-east-1:123456789012:accesspoint/ap/object/source.txt"},
		{name: "bad escape", raw: "test-bucket/bad%zz"},
		{name: "unsupported query", raw: "test-bucket/source.txt?partNumber=1"},
		{name: "empty version", raw: "test-bucket/source.txt?versionId="},
		{name: "duplicate version", raw: "test-bucket/source.txt?versionId=v1&versionId=v2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseCopySource(tt.raw, "test-bucket")
			require.Error(t, err)
		})
	}
}

func TestRewriteCopySource(t *testing.T) {
	cfg := &VBucketConfig{RealBucket: "real-bucket"}

	got, err := rewriteCopySource("/test-bucket/source%20one.txt?versionId=v%2F1", "test-bucket", cfg, "tenant-abc/")
	require.NoError(t, err)

	assert.Equal(t, "real-bucket/tenant-abc/source%20one.txt?versionId=v%2F1", got)
}

func TestBuildCopySourceEscapesPathAndQuery(t *testing.T) {
	got := buildCopySource("real-bucket", "tenant-abc/space and+plus%25.txt", "v/1")

	assert.Equal(t, "real-bucket/tenant-abc/space%20and+plus%2525.txt?versionId=v%2F1", got)
}
