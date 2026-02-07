package http_server

// TODO: Implement real IAM permission checking.
// This should verify that the virtual credentials have permissions for the
// requested action (e.g. s3:GetObject, s3:PutObject, s3:ListBucket, etc.)
// against the resolved bucket and object key.
//
// For now this unconditionally allows all actions.
func checkIAMPermissions(accessKeyID, bucket, objectKey, action string) error {
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
