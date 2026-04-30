package http_server

import (
	"encoding/xml"
	"io"
	"net/url"
	"strings"
)

// bucketSubresources are S3 bucket-level query params that indicate
// non-list operations (GetBucketVersioning, GetBucketAcl, etc.).
// If any of these appear in the query string, the request is NOT a list request.
var bucketSubresources = map[string]bool{
	"acl": true, "cors": true, "lifecycle": true, "policy": true,
	"versioning": true, "tagging": true, "encryption": true,
	"notification": true, "replication": true, "website": true,
	"logging": true, "accelerate": true, "analytics": true,
	"inventory": true, "metrics": true, "publicAccessBlock": true,
	"ownershipControls": true, "intelligent-tiering": true,
	"object-lock": true, "location": true,
	// These are list-like but have different response schemas;
	// treat them as subresources for now until we add dedicated rewriting.
	"versions": true, "uploads": true,
}

func isListObjectsRequest(method string, objectKey string, rawQuery string) bool {
	if method != "GET" || objectKey != "" {
		return false
	}
	query, _ := url.ParseQuery(rawQuery)
	for key := range query {
		if bucketSubresources[key] {
			return false
		}
	}
	return true
}

// rewriteListQueryForPrefix prepends pathPrefix to the prefix, start-after,
// and marker query parameters used by ListObjects V1/V2.
func rewriteListQueryForPrefix(rawQuery string, pathPrefix string) string {
	q, _ := url.ParseQuery(rawQuery)

	q.Set("prefix", pathPrefix+q.Get("prefix"))

	if sa := q.Get("start-after"); sa != "" {
		q.Set("start-after", pathPrefix+sa)
	}
	if m := q.Get("marker"); m != "" {
		q.Set("marker", pathPrefix+m)
	}

	return q.Encode()
}

func listResponseUsesURLEncoding(rawQuery string) bool {
	q, _ := url.ParseQuery(rawQuery)
	return q.Get("encoding-type") == "url"
}

// rewriteListResponse rewrites a ListObjects V1/V2 XML response:
//   - strips pathPrefix from object keys, prefix echo, and common prefixes
//   - replaces the echoed bucket name with the virtual bucket name
//
// Uses streaming XML token rewriting so unknown elements are preserved.
func rewriteListResponse(in io.Reader, out io.Writer, pathPrefix, virtualBucket string, urlEncoded bool) error {
	decoder := xml.NewDecoder(in)
	encoder := xml.NewEncoder(out)
	var stack []string

	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch t := token.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			if err := encoder.EncodeToken(t); err != nil {
				return err
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if err := encoder.EncodeToken(t); err != nil {
				return err
			}
		case xml.CharData:
			path := strings.Join(stack, "/")
			text := string(t)
			switch path {
			case "ListBucketResult/Name":
				text = virtualBucket
			case "ListBucketResult/Prefix",
				"ListBucketResult/StartAfter",
				"ListBucketResult/Marker",
				"ListBucketResult/NextMarker",
				"ListBucketResult/CommonPrefixes/Prefix",
				"ListBucketResult/Contents/Key":
				text = stripListPathPrefix(text, pathPrefix, urlEncoded)
			}
			if err := encoder.EncodeToken(xml.CharData(text)); err != nil {
				return err
			}
		default:
			if err := encoder.EncodeToken(t); err != nil {
				return err
			}
		}
	}

	return encoder.Flush()
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
