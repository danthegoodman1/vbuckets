package http_server

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type s3ContractEntry struct {
	id        string
	operation string
	method    string
	target    string
	bucket    string
	object    string
	headers   http.Header
	actions   []string
	response  string
}

// s3OperationContract is the executable index for the exact request planner
// matrix in README.md. Phase 2 implements the remaining response transforms.
var s3OperationContract = []s3ContractEntry{
	{"C-S3-001", "ListBuckets", http.MethodGet, "/", "", "", nil, []string{"s3:ListAllMyBuckets"}, "R1"},
	{"C-S3-002", "CreateBucket", http.MethodPut, "/photos", "photos", "", nil, []string{"s3:CreateBucket"}, "R2"},
	{"C-S3-003", "HeadBucket", http.MethodHead, "/photos", "photos", "", nil, []string{"s3:ListBucket"}, "R3"},
	{"C-S3-004", "ListObjects V1", http.MethodGet, "/photos?prefix=2026%2F", "photos", "", nil, []string{"s3:ListBucket"}, "R5"},
	{"C-S3-005", "ListObjects V2", http.MethodGet, "/photos?list-type=2&prefix=2026%2F", "photos", "", nil, []string{"s3:ListBucket"}, "R5"},
	{"C-S3-006", "ListMultipartUploads", http.MethodGet, "/photos?uploads", "photos", "", nil, []string{"s3:ListBucketMultipartUploads"}, "R6"},
	{"C-S3-007", "GetObject", http.MethodGet, "/photos/cat.jpg", "photos", "cat.jpg", nil, []string{"s3:GetObject"}, "R4"},
	{"C-S3-008", "HeadObject", http.MethodHead, "/photos/cat.jpg", "photos", "cat.jpg", nil, []string{"s3:GetObject"}, "R3"},
	{"C-S3-009", "GetObjectVersion", http.MethodGet, "/photos/cat.jpg?versionId=v1", "photos", "cat.jpg", nil, []string{"s3:GetObjectVersion"}, "R4"},
	{"C-S3-010", "HeadObjectVersion", http.MethodHead, "/photos/cat.jpg?versionId=v1", "photos", "cat.jpg", nil, []string{"s3:GetObjectVersion"}, "R3"},
	{"C-S3-011", "PutObject", http.MethodPut, "/photos/cat.jpg", "photos", "cat.jpg", nil, []string{"s3:PutObject"}, "R3"},
	{"C-S3-012", "PutObjectAcl", http.MethodPut, "/photos/cat.jpg?acl", "photos", "cat.jpg", nil, []string{"s3:PutObjectAcl"}, "R3"},
	{"C-S3-013", "PutObjectTagging", http.MethodPut, "/photos/cat.jpg?tagging", "photos", "cat.jpg", nil, []string{"s3:PutObjectTagging"}, "R3"},
	{"C-S3-014", "CopyObject", http.MethodPut, "/photos/copy.jpg", "photos", "copy.jpg", http.Header{"X-Amz-Copy-Source": []string{"/photos/cat.jpg"}}, []string{"s3:PutObject", "s3:GetObject"}, "R10"},
	{"C-S3-015", "DeleteObject", http.MethodDelete, "/photos/cat.jpg", "photos", "cat.jpg", nil, []string{"s3:DeleteObject"}, "R3"},
	{"C-S3-016", "DeleteObjectVersion", http.MethodDelete, "/photos/cat.jpg?versionId=v1", "photos", "cat.jpg", nil, []string{"s3:DeleteObjectVersion"}, "R3"},
	{"C-S3-017", "CreateMultipartUpload", http.MethodPost, "/photos/video.mp4?uploads", "photos", "video.mp4", nil, []string{"s3:PutObject"}, "R7"},
	{"C-S3-018", "UploadPart", http.MethodPut, "/photos/video.mp4?partNumber=1&uploadId=u1", "photos", "video.mp4", nil, []string{"s3:PutObject"}, "R3"},
	{"C-S3-019", "ListParts", http.MethodGet, "/photos/video.mp4?uploadId=u1", "photos", "video.mp4", nil, []string{"s3:ListMultipartUploadParts"}, "R8"},
	{"C-S3-020", "CompleteMultipartUpload", http.MethodPost, "/photos/video.mp4?uploadId=u1", "photos", "video.mp4", nil, []string{"s3:PutObject"}, "R9"},
	{"C-S3-021", "AbortMultipartUpload", http.MethodDelete, "/photos/video.mp4?uploadId=u1", "photos", "video.mp4", nil, []string{"s3:AbortMultipartUpload"}, "R3"},
}

var s3ResponseProfiles = map[string]string{
	"R1":  "local list-buckets XML",
	"R2":  "local create-bucket XML",
	"R3":  "safe headers only",
	"R4":  "streamed object",
	"R5":  "ListObjects XML",
	"R6":  "ListMultipartUploads XML",
	"R7":  "CreateMultipartUpload XML",
	"R8":  "ListParts XML",
	"R9":  "CompleteMultipartUpload XML",
	"R10": "CopyObject XML",
}

// TestS3OperationContract is the executable index for the operation matrix in
// README.md. Each stable C-S3 identifier has one representative accepted wire
// shape, its IAM action set, and its response-virtualization profile. Rejection
// cases for each row belong to the same identifier as the grammar is hardened.
func TestS3OperationContract(t *testing.T) {
	readmeBytes, err := os.ReadFile("../README.md")
	require.NoError(t, err)
	readme := string(readmeBytes)

	require.Len(t, s3OperationContract, 21)
	seenIDs := make(map[string]bool, len(s3OperationContract))
	seenOperations := make(map[string]bool, len(s3OperationContract))
	usedProfiles := make(map[string]bool, len(s3ResponseProfiles))

	for i, tt := range s3OperationContract {
		expectedID := fmt.Sprintf("C-S3-%03d", i+1)
		require.Equal(t, expectedID, tt.id, "contract identifiers must be contiguous and ordered")
		require.Falsef(t, seenIDs[tt.id], "duplicate contract identifier %s", tt.id)
		require.Falsef(t, seenOperations[tt.operation], "duplicate operation name %s", tt.operation)
		seenIDs[tt.id] = true
		seenOperations[tt.operation] = true
		usedProfiles[tt.response] = true

		_, knownProfile := s3ResponseProfiles[tt.response]
		require.Truef(t, knownProfile, "%s uses unknown response profile %s", tt.id, tt.response)
		readmeRowPrefix := fmt.Sprintf("| %s | %s |", tt.id, tt.operation)
		require.Equalf(t, 1, strings.Count(readme, readmeRowPrefix), "%s must have exactly one README row", tt.id)

		t.Run(tt.id, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.target, nil)
			require.NoError(t, err)
			for name, values := range tt.headers {
				for _, value := range values {
					req.Header.Add(name, value)
				}
			}

			plan, err := planS3Operation(req, tt.bucket, tt.object)
			require.NoError(t, err)
			expectedKind := strings.ReplaceAll(tt.operation, " ", "")
			if expectedKind == "ListObjectsV1" {
				expectedKind = "ListObjects"
			}
			require.Equal(t, S3OperationKind(expectedKind), plan.Kind())
			require.Equal(t, S3ResponseProfile(tt.response), plan.ResponseProfile())
			require.Equal(t, contractBodyKind(tt.operation), plan.bodyKind)
			checks := plan.iamChecks
			actions := make([]string, len(checks))
			for i := range checks {
				actions[i] = checks[i].Action
			}
			require.Equal(t, tt.actions, actions)
		})
	}

	for profile := range s3ResponseProfiles {
		require.Truef(t, usedProfiles[profile], "response profile %s is not assigned to an operation", profile)
		require.Truef(t, strings.Contains(readme, "| "+profile+" |"), "response profile %s is missing from README.md", profile)
	}
}

func TestS3OperationContractRejectsUnknownQueryAcrossAllRows(t *testing.T) {
	for _, tt := range s3OperationContract {
		t.Run(tt.id, func(t *testing.T) {
			separator := "?"
			if strings.Contains(tt.target, "?") {
				separator = "&"
			}
			req, err := http.NewRequest(tt.method, tt.target+separator+"unsupported-contract-key=value", nil)
			require.NoError(t, err)
			req.Header = tt.headers.Clone()
			_, err = planS3Operation(req, tt.bucket, tt.object)
			require.ErrorIs(t, err, ErrUnsupportedS3Operation)
		})
	}
}

func TestS3OperationContractAcceptsAllowedQueryCombinations(t *testing.T) {
	tests := []struct {
		name   string
		method string
		target string
		object string
		kind   S3OperationKind
	}{
		{name: "ListObjects V1", method: http.MethodGet, target: "/bucket?prefix=&delimiter=%2F&marker=m&max-keys=1000&encoding-type=url&x-id=ListObjects", kind: operationListObjects},
		{name: "ListObjects V2", method: http.MethodGet, target: "/bucket?list-type=2&prefix=p&delimiter=%2F&continuation-token=t&fetch-owner=true&max-keys=1000&encoding-type=url&start-after=s&x-id=ListObjectsV2", kind: operationListObjectsV2},
		{name: "ListMultipartUploads", method: http.MethodGet, target: "/bucket?uploads&delimiter=%2F&encoding-type=url&key-marker=k&max-uploads=1000&prefix=p&upload-id-marker=u&x-id=ListMultipartUploads", kind: operationListMultipartUploads},
		{name: "GetObjectVersion", method: http.MethodGet, target: "/bucket/key?versionId=v&partNumber=1&response-cache-control=no-cache&response-content-disposition=inline&response-content-encoding=gzip&response-content-language=en&response-content-type=text%2Fplain&response-expires=tomorrow&x-id=GetObject", object: "key", kind: operationGetObjectVersion},
		{name: "HeadObjectVersion", method: http.MethodHead, target: "/bucket/key?versionId=v&partNumber=1&x-id=HeadObject", object: "key", kind: operationHeadObjectVersion},
		{name: "ListParts", method: http.MethodGet, target: "/bucket/key?uploadId=u&max-parts=1000&part-number-marker=1&x-id=ListParts", object: "key", kind: operationListParts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.target, nil)
			require.NoError(t, err)
			plan, err := planS3Operation(req, "bucket", tt.object)
			require.NoError(t, err)
			require.Equal(t, tt.kind, plan.kind)
		})
	}
}

func TestS3OperationContractExactXIDGrammar(t *testing.T) {
	for _, tt := range s3OperationContract {
		t.Run(tt.id, func(t *testing.T) {
			separator := "?"
			if strings.Contains(tt.target, "?") {
				separator = "&"
			}
			for _, test := range []struct {
				name    string
				suffix  string
				wantErr bool
			}{
				{name: "matching", suffix: separator + "x-id=" + contractXID(tt.operation)},
				{name: "mismatched", suffix: separator + "x-id=DefinitelyWrong", wantErr: true},
				{name: "duplicate", suffix: separator + "x-id=" + contractXID(tt.operation) + "&x-id=" + contractXID(tt.operation), wantErr: true},
			} {
				t.Run(test.name, func(t *testing.T) {
					req, err := http.NewRequest(tt.method, tt.target+test.suffix, nil)
					require.NoError(t, err)
					req.Header = tt.headers.Clone()
					_, err = planS3Operation(req, tt.bucket, tt.object)
					if test.wantErr {
						require.ErrorIs(t, err, ErrUnsupportedS3Operation)
					} else {
						require.NoError(t, err)
					}
				})
			}
		})
	}
}

func contractXID(operation string) string {
	switch operation {
	case "ListObjects V1":
		return "ListObjects"
	case "ListObjects V2":
		return "ListObjectsV2"
	case "GetObjectVersion":
		return "GetObject"
	case "HeadObjectVersion":
		return "HeadObject"
	case "DeleteObjectVersion":
		return "DeleteObject"
	default:
		return strings.ReplaceAll(operation, " ", "")
	}
}

func contractBodyKind(operation string) s3BodyKind {
	switch operation {
	case "PutObject", "PutObjectAcl", "PutObjectTagging", "UploadPart":
		return bodyStreaming
	case "CreateBucket":
		return bodyCreateBucketConfiguration
	case "CompleteMultipartUpload":
		return bodyCompleteMultipartXML
	default:
		return bodyEmpty
	}
}
