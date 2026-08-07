package http_server

import (
	"net/url"
	"strings"
)

func rewriteOutboundQuery(kind S3OperationKind, rawQuery, pathPrefix string, prefixKeyFields bool, cfg *VBucketConfig) (string, error) {
	q, _ := url.ParseQuery(rawQuery)
	if prefixKeyFields && pathPrefix != "" {
		q.Set("prefix", pathPrefix+q.Get("prefix"))
	}

	var keyFields []string
	switch kind {
	case operationListObjects:
		keyFields = []string{"marker"}
	case operationListObjectsV2:
		keyFields = []string{"start-after"}
	case operationListMultipartUploads:
		keyFields = []string{"key-marker"}
	}
	for _, field := range keyFields {
		if value := q.Get(field); value != "" && pathPrefix != "" {
			q.Set(field, pathPrefix+value)
		}
	}
	if cfg != nil {
		for _, field := range []struct {
			name string
			kind string
		}{
			{name: "continuation-token", kind: "continuation"},
			{name: "upload-id-marker", kind: "upload"},
			{name: "uploadId", kind: "upload"},
			{name: "versionId", kind: "version"},
		} {
			if value := q.Get(field.name); value != "" {
				decoded, err := decodeOpaqueToken(cfg, field.kind, value)
				if err != nil {
					return "", err
				}
				q.Set(field.name, decoded)
			}
		}
	}
	return q.Encode(), nil
}

func stripListPathPrefix(text, pathPrefix string, urlEncoded bool) string {
	if !urlEncoded {
		return strings.TrimPrefix(text, pathPrefix)
	}

	decoded, err := url.PathUnescape(text)
	if err != nil {
		return strings.TrimPrefix(text, awsURIEncode(pathPrefix))
	}
	return awsURIEncode(strings.TrimPrefix(decoded, pathPrefix))
}
