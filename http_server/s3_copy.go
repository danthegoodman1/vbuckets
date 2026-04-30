package http_server

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const copySourceHeader = "x-amz-copy-source"

type copySource struct {
	Bucket    string
	Key       string
	VersionID string
}

func parseCopySource(raw, expectedBucket string) (*copySource, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("copy source is required")
	}

	lower := strings.ToLower(raw)
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "arn:") {
		return nil, fmt.Errorf("copy source must be a bucket/key path")
	}

	raw = strings.TrimPrefix(raw, "/")
	pathPart, rawQuery, _ := strings.Cut(raw, "?")
	if pathPart == "" {
		return nil, fmt.Errorf("copy source path is required")
	}

	bucketPart, keyPart, ok := strings.Cut(pathPart, "/")
	if !ok || keyPart == "" {
		return nil, fmt.Errorf("copy source must include bucket and key")
	}
	if strings.Contains(bucketPart, ":") {
		return nil, fmt.Errorf("copy source bucket is invalid")
	}

	bucket, err := url.PathUnescape(bucketPart)
	if err != nil {
		return nil, fmt.Errorf("decode copy source bucket: %w", err)
	}
	key, err := url.PathUnescape(keyPart)
	if err != nil {
		return nil, fmt.Errorf("decode copy source key: %w", err)
	}
	if bucket != expectedBucket {
		return nil, fmt.Errorf("copy source bucket %q does not match destination bucket %q", bucket, expectedBucket)
	}

	source := &copySource{
		Bucket: bucket,
		Key:    key,
	}
	if rawQuery != "" {
		query, err := url.ParseQuery(rawQuery)
		if err != nil {
			return nil, fmt.Errorf("parse copy source query: %w", err)
		}
		for key := range query {
			if key != "versionId" {
				return nil, fmt.Errorf("unsupported copy source query parameter %q", key)
			}
		}
		versionIDs := query["versionId"]
		if len(versionIDs) != 1 {
			return nil, fmt.Errorf("copy source must include exactly one versionId")
		}
		source.VersionID = versionIDs[0]
		if source.VersionID == "" {
			return nil, fmt.Errorf("copy source versionId must not be empty")
		}
	}

	return source, nil
}

func rewriteCopySource(raw, virtualBucket string, cfg *VBucketConfig, normalizedPrefix string) (string, error) {
	source, err := parseCopySource(raw, virtualBucket)
	if err != nil {
		return "", err
	}

	realKey := normalizedPrefix + source.Key
	return buildCopySource(cfg.RealBucket, realKey, source.VersionID), nil
}

func buildCopySource(bucket, key, versionID string) string {
	u := url.URL{Path: "/" + bucket + "/" + key}
	escaped := strings.TrimPrefix(u.EscapedPath(), "/")
	if versionID == "" {
		return escaped
	}

	query := url.Values{}
	query.Set("versionId", versionID)
	return escaped + "?" + query.Encode()
}

func isCopyObjectRequest(r *http.Request) bool {
	return hasHeader(r, copySourceHeader)
}
