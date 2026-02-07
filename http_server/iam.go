package http_server

// IAMPolicy defines what actions a virtual access key is allowed to perform.
// Evaluated after bucket resolution so the policy can reference bucket names
// and key prefixes.
//
// TODO: Define the real policy structure (e.g. a list of statements with
// effect/action/resource matching, similar to AWS IAM policies).
type IAMPolicy struct{}

// TODO: Implement real IAM permission checking.
// This should evaluate the policy statements against the requested action,
// bucket, and object key.
//
// For now this unconditionally allows all actions.
func checkIAMPermissions(policy IAMPolicy, bucket, objectKey, action string) error {
	return nil
}

// s3ActionFromRequest derives the S3 IAM action string from the HTTP method
// and request context. This is a rough mapping -- real S3 has more granular
// actions based on query parameters (e.g. ?uploads, ?acl, ?versioning).
func s3ActionFromRequest(method string) string {
	switch method {
	case "GET", "HEAD":
		return "s3:GetObject"
	case "PUT":
		return "s3:PutObject"
	case "DELETE":
		return "s3:DeleteObject"
	case "POST":
		return "s3:PutObject" // multipart uploads, etc.
	default:
		return "s3:Unknown"
	}
}
