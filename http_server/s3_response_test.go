package http_server

import (
	"bytes"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func responseTestConfig() *VBucketConfig {
	return &VBucketConfig{
		RealEndpoint: "https://origin.example.com", RealBucket: "real-bucket",
		RealAccessKey: "ORIGINACCESS123", RealSecretKey: "ORIGINSECRET456", RealRegion: "us-east-1",
		PathPrefix: "tenant-a", RealUsePathStyle: true, RoutingTokenKey: testRoutingTokenKey,
	}
}

func responseTestPlan(profile S3ResponseProfile) *S3OperationPlan {
	return &S3OperationPlan{
		kind: operationGetObject, bucket: "virtual-bucket", objectKey: "dir/a +%/file.txt",
		responseProfile: profile, query: make(url.Values), forwardHeaders: make(http.Header),
	}
}

func writeResponseForTest(t *testing.T, request *http.Request, plan *S3OperationPlan, status int, headers http.Header, body string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	if headers == nil {
		headers = make(http.Header)
	}
	response := &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
	recorder := httptest.NewRecorder()
	err := writeVirtualizedUpstreamResponse(recorder, request, response, plan, responseTestConfig(), "tenant-a/")
	return recorder, err
}

func TestResponseProfilesPreserveOnlySemanticallyValidRepresentations(t *testing.T) {
	request := httptest.NewRequest(http.MethodPut, "http://proxy.example/virtual-bucket/key", nil)

	t.Run("R3 discards body but preserves operation result validators", func(t *testing.T) {
		plan := responseTestPlan(responseSafeHeaders)
		plan.kind = operationPutObject
		headers := http.Header{
			"Content-Length":        {"999"},
			"Content-Encoding":      {"gzip"},
			"Etag":                  {`"stored-etag"`},
			"X-Amz-Checksum-Sha256": {"stored-checksum"},
			"X-Amz-Version-Id":      {"origin-version"},
		}
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, headers, "real-bucket tenant-a/ leak")
		require.NoError(t, err)
		assert.Empty(t, recorder.Body.String())
		assert.Empty(t, recorder.Header().Get("Content-Length"))
		assert.Empty(t, recorder.Header().Get("Content-Encoding"))
		assert.Equal(t, `"stored-etag"`, recorder.Header().Get("Etag"))
		assert.Equal(t, "stored-checksum", recorder.Header().Get("X-Amz-Checksum-Sha256"))
		virtualVersion := recorder.Header().Get("X-Amz-Version-Id")
		assert.NotEqual(t, "origin-version", virtualVersion)
		decoded, err := decodeOpaqueToken(responseTestConfig(), "version", virtualVersion)
		require.NoError(t, err)
		assert.Equal(t, "origin-version", decoded)
	})

	t.Run("R4 streams object and user metadata byte for byte", func(t *testing.T) {
		plan := responseTestPlan(responseStreamObject)
		body := "opaque real-bucket tenant-a/ object bytes"
		headers := http.Header{
			"X-Amz-Meta-Note":     {"real-bucket tenant-a/ belongs to user"},
			"Content-Disposition": {`attachment; filename="real-bucket-tenant-a.txt"`},
			"Cache-Control":       {"private, real-bucket tenant-a/ user-value"},
			"X-Amz-Restore":       {`ongoing-request="false", origin="real-bucket/tenant-a"`},
		}
		recorder, err := writeResponseForTest(t, httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket/key", nil), plan, http.StatusOK, headers, body)
		require.NoError(t, err)
		assert.Equal(t, body, recorder.Body.String())
		assert.Equal(t, headers.Get("X-Amz-Meta-Note"), recorder.Header().Get("X-Amz-Meta-Note"))
		assert.Equal(t, headers.Get("Content-Disposition"), recorder.Header().Get("Content-Disposition"))
		assert.Equal(t, headers.Get("Cache-Control"), recorder.Header().Get("Cache-Control"))
		assert.Empty(t, recorder.Header().Get("X-Amz-Restore"), "routing-owned headers that reveal mapping identifiers are dropped")
	})

	t.Run("R5 drops stale representation validators", func(t *testing.T) {
		plan := responseTestPlan(responseListObjects)
		plan.objectKey = ""
		headers := http.Header{"Content-Length": {"999"}, "Etag": {`"xml-etag"`}, "X-Amz-Checksum-Sha256": {"xml-checksum"}}
		body := `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-a/a.txt</Key></Contents></ListBucketResult>`
		recorder, err := writeResponseForTest(t, httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket", nil), plan, http.StatusOK, headers, body)
		require.NoError(t, err)
		assert.Contains(t, recorder.Body.String(), `<Name>virtual-bucket</Name>`)
		assert.Contains(t, recorder.Body.String(), `<Key>a.txt</Key>`)
		assert.Empty(t, recorder.Header().Get("Content-Length"))
		assert.Empty(t, recorder.Header().Get("Etag"))
		assert.Empty(t, recorder.Header().Get("X-Amz-Checksum-Sha256"))
	})

	t.Run("R10 preserves stored-object ETag and omits extensions", func(t *testing.T) {
		plan := responseTestPlan(responseCopyObject)
		plan.kind = operationCopyObject
		body := `<CopyObjectResult backend="real-bucket"><ETag>tenant-a/opaque-etag</ETag><LastModified>2026-08-06T00:00:00Z</LastModified><Extension><Key>tenant-a/foreign</Key></Extension></CopyObjectResult>`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, http.Header{"X-Amz-Checksum-Sha256": {"stored-checksum"}}, body)
		require.NoError(t, err)
		assert.Contains(t, recorder.Body.String(), `<ETag>tenant-a/opaque-etag</ETag>`)
		assert.NotContains(t, recorder.Body.String(), "Extension")
		assert.NotContains(t, recorder.Body.String(), "backend=")
		assert.Equal(t, "stored-checksum", recorder.Header().Get("X-Amz-Checksum-Sha256"))
	})
}

func TestResponseErrorRedirectAndNotModifiedHandling(t *testing.T) {
	plan := responseTestPlan(responseStreamObject)
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket/dir/a%20+%25/file.txt", nil)

	t.Run("valid error keeps finite safe code and drops body validators", func(t *testing.T) {
		headers := http.Header{
			"Etag": {"error-etag"}, "X-Amz-Checksum-Sha256": {"error-checksum"}, "Content-Encoding": {"gzip"},
			"Content-Disposition": {`attachment; filename="real-bucket-tenant-a.txt"`},
			"X-Amz-Meta-Backend":  {"real-bucket/tenant-a"},
		}
		recorder, err := writeResponseForTest(t, request, plan, http.StatusNotFound, headers, `<Error><Code>NoSuchKey</Code><Message>origin details</Message></Error>`)
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotFound, recorder.Code)
		assert.Contains(t, recorder.Body.String(), `<Code>NoSuchKey</Code>`)
		assert.NotContains(t, recorder.Body.String(), "origin details")
		assert.Empty(t, recorder.Header().Get("Etag"))
		assert.Empty(t, recorder.Header().Get("X-Amz-Checksum-Sha256"))
		assert.Empty(t, recorder.Header().Get("Content-Encoding"))
		assert.Empty(t, recorder.Header().Get("Content-Disposition"))
		assert.Empty(t, recorder.Header().Get("X-Amz-Meta-Backend"))
	})

	for name, body := range map[string]string{
		"malformed":         `<Error><Code>NoSuchKey`,
		"foreign namespace": `<Error xmlns="urn:foreign"><Code>NoSuchKey</Code></Error>`,
		"oversize":          `<Error><Code>NoSuchKey</Code><Message>` + strings.Repeat("x", maxS3ControlResponseBytes) + `</Message></Error>`,
	} {
		t.Run(name+" becomes 502", func(t *testing.T) {
			recorder, err := writeResponseForTest(t, request, plan, http.StatusNotFound, nil, body)
			require.Error(t, err)
			assert.Equal(t, http.StatusBadGateway, recorder.Code)
			assert.Contains(t, recorder.Body.String(), `<Code>InternalError</Code>`)
		})
	}

	t.Run("redirect becomes controlled failure without a self-loop", func(t *testing.T) {
		recorder, err := writeResponseForTest(t, request, plan, http.StatusTemporaryRedirect, http.Header{"Location": {"https://origin.example.com/real-bucket/tenant-a/leak"}}, "")
		require.Error(t, err)
		assert.Equal(t, http.StatusBadGateway, recorder.Code)
		assert.Empty(t, recorder.Header().Get("Location"))
		assert.NotContains(t, recorder.Body.String(), "origin.example.com")
	})

	t.Run("HEAD redirect also becomes controlled failure", func(t *testing.T) {
		headRequest := httptest.NewRequest(http.MethodHead, request.URL.String(), nil)
		recorder, err := writeResponseForTest(t, headRequest, plan, http.StatusMovedPermanently, http.Header{"Location": {"https://origin.example.com/leak"}}, "")
		require.Error(t, err)
		assert.Equal(t, http.StatusBadGateway, recorder.Code)
		assert.Empty(t, recorder.Header().Get("Location"))
	})

	t.Run("upstream error code is structurally validated then synthesized", func(t *testing.T) {
		recorder, err := writeResponseForTest(t, request, plan, http.StatusBadRequest, nil, `<Error><Code>InvalidORIGINACCESS123Token</Code><Message>details</Message></Error>`)
		require.NoError(t, err)
		assert.Equal(t, http.StatusBadRequest, recorder.Code)
		assert.Contains(t, recorder.Body.String(), `<Code>InvalidRequest</Code>`)
		assert.NotContains(t, recorder.Body.String(), "ORIGINACCESS123")
	})

	t.Run("finite compatible 404 codes retain SDK semantics", func(t *testing.T) {
		for _, test := range []struct {
			name string
			kind S3OperationKind
			code string
		}{
			{name: "bucket", kind: operationListObjects, code: "NoSuchBucket"},
			{name: "key", kind: operationGetObject, code: "NoSuchKey"},
			{name: "version", kind: operationGetObjectVersion, code: "NoSuchVersion"},
			{name: "upload", kind: operationListParts, code: "NoSuchUpload"},
			{name: "copy source key", kind: operationCopyObject, code: "NoSuchKey"},
			{name: "copy source version", kind: operationCopyObject, code: "NoSuchVersion"},
		} {
			t.Run(test.name, func(t *testing.T) {
				codePlan := responseTestPlan(responseStreamObject)
				codePlan.kind = test.kind
				recorder, err := writeResponseForTest(t, request, codePlan, http.StatusNotFound, nil, `<Error><Code>`+test.code+`</Code><Message>backend detail</Message></Error>`)
				require.NoError(t, err)
				assert.Contains(t, recorder.Body.String(), `<Code>`+test.code+`</Code>`)
				assert.NotContains(t, recorder.Body.String(), "backend detail")
			})
		}
	})

	t.Run("incompatible finite code falls back to operation status", func(t *testing.T) {
		recorder, err := writeResponseForTest(t, request, plan, http.StatusNotFound, nil, `<Error><Code>NoSuchUpload</Code></Error>`)
		require.NoError(t, err)
		assert.Contains(t, recorder.Body.String(), `<Code>NoSuchKey</Code>`)
		assert.NotContains(t, recorder.Body.String(), `<Code>NoSuchUpload</Code>`)
	})

	t.Run("304 is empty and has no Location", func(t *testing.T) {
		recorder, err := writeResponseForTest(t, request, plan, http.StatusNotModified, http.Header{"Etag": {`"cached"`}, "Location": {"https://origin/leak"}}, "not xml")
		require.NoError(t, err)
		assert.Equal(t, http.StatusNotModified, recorder.Code)
		assert.Empty(t, recorder.Body.String())
		assert.Equal(t, `"cached"`, recorder.Header().Get("Etag"))
		assert.Empty(t, recorder.Header().Get("Location"))
	})
}

func TestBoundedSuccessRequiresMappingFieldsAndEscapesVirtualLocation(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://proxy.example/virtual-bucket/dir/a%20+%25/file.txt?uploadId=token", nil)
	plan := responseTestPlan(responseCompleteMultipart)
	plan.kind = operationCompleteMultipartUpload
	valid := `<CompleteMultipartUploadResult><Location>https://origin.example.com/encoded</Location><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key><ETag>etag</ETag></CompleteMultipartUploadResult>`
	recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, valid)
	require.NoError(t, err)
	assert.Contains(t, recorder.Body.String(), `<Location>/virtual-bucket/dir%2Fa%20%2B%25%2Ffile.txt</Location>`)
	assert.NotContains(t, recorder.Body.String(), "origin.example.com")
	assert.NotContains(t, recorder.Body.String(), "proxy.example", "public origin inference belongs to trusted-terminator configuration")

	tests := map[S3ResponseProfile]string{
		responseCreateMultipart:   `<InitiateMultipartUploadResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key></InitiateMultipartUploadResult>`,
		responseListParts:         `<ListPartsResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key></ListPartsResult>`,
		responseCompleteMultipart: `<CompleteMultipartUploadResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key><ETag>etag</ETag></CompleteMultipartUploadResult>`,
		responseCopyObject:        `<CopyObjectResult><ETag>etag</ETag></CopyObjectResult>`,
	}
	for profile, body := range tests {
		t.Run(string(profile), func(t *testing.T) {
			invalidPlan := responseTestPlan(profile)
			recorder, err := writeResponseForTest(t, request, invalidPlan, http.StatusOK, nil, body)
			require.Error(t, err)
			assert.Equal(t, http.StatusBadGateway, recorder.Code)
		})
	}

	t.Run("ListParts rejects mismatched upload echo before commit", func(t *testing.T) {
		virtualUpload, err := encodeOpaqueToken(responseTestConfig(), "upload", "origin-upload")
		require.NoError(t, err)
		listPlan := responseTestPlan(responseListParts)
		listPlan.query.Set("uploadId", virtualUpload)
		body := `<ListPartsResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key><UploadId>wrong-upload</UploadId><PartNumberMarker>0</PartNumberMarker><NextPartNumberMarker>0</NextPartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated></ListPartsResult>`
		recorder, err := writeResponseForTest(t, request, listPlan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadGateway, recorder.Code)
		assert.NotContains(t, recorder.Body.String(), "wrong-upload")
	})

	t.Run("ListParts permits an absent next marker only when complete", func(t *testing.T) {
		virtualUpload, err := encodeOpaqueToken(responseTestConfig(), "upload", "origin-upload")
		require.NoError(t, err)
		listPlan := responseTestPlan(responseListParts)
		listPlan.query.Set("uploadId", virtualUpload)
		body := `<ListPartsResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key><UploadId>origin-upload</UploadId><PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated></ListPartsResult>`
		recorder, err := writeResponseForTest(t, request, listPlan, http.StatusOK, nil, body)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, recorder.Code)
	})

	for name, pagination := range map[string]string{
		"truncated without next marker": `<PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>true</IsTruncated>`,
		"nonnumeric marker":             `<PartNumberMarker>NaN</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated>`,
		"nonnumeric max parts":          `<PartNumberMarker>0</PartNumberMarker><MaxParts>many</MaxParts><IsTruncated>false</IsTruncated>`,
		"invalid truncation flag":       `<PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>maybe</IsTruncated>`,
	} {
		t.Run("ListParts rejects "+name, func(t *testing.T) {
			virtualUpload, err := encodeOpaqueToken(responseTestConfig(), "upload", "origin-upload")
			require.NoError(t, err)
			listPlan := responseTestPlan(responseListParts)
			listPlan.query.Set("uploadId", virtualUpload)
			body := `<ListPartsResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key><UploadId>origin-upload</UploadId>` + pagination + `</ListPartsResult>`
			recorder, err := writeResponseForTest(t, request, listPlan, http.StatusOK, nil, body)
			require.Error(t, err)
			assert.Equal(t, http.StatusBadGateway, recorder.Code)
		})
	}

	t.Run("nested markup in a mandatory scalar fails before commit", func(t *testing.T) {
		copyPlan := responseTestPlan(responseCopyObject)
		copyPlan.kind = operationCopyObject
		body := `<CopyObjectResult><ETag>before<Extension/>after</ETag><LastModified>2026-08-06T00:00:00Z</LastModified></CopyObjectResult>`
		recorder, err := writeResponseForTest(t, request, copyPlan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.Equal(t, http.StatusBadGateway, recorder.Code)
		assert.NotContains(t, recorder.Body.String(), "before")
	})
}

func TestResponseHeaderValidationIsAtomic(t *testing.T) {
	plan := responseTestPlan(responseStreamObject)
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket/key", nil)
	headers := http.Header{
		"Content-Length":   {"12345"},
		"Etag":             {`"upstream-etag"`},
		"X-Amz-Version-Id": {""},
	}
	recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, headers, "upstream body")
	require.Error(t, err)
	assert.Equal(t, http.StatusBadGateway, recorder.Code)
	assert.Empty(t, recorder.Header().Get("Etag"))
	assert.NotEqual(t, "12345", recorder.Header().Get("Content-Length"))
	assert.Empty(t, recorder.Header().Get("X-Amz-Version-Id"))
	assert.NotContains(t, recorder.Body.String(), "upstream body")
}

func TestSensitiveBackendHostnameFilteringHandlesPortsAndCase(t *testing.T) {
	config := responseTestConfig()
	config.RealEndpoint = "https://Origin.Example:9000"
	plan := responseTestPlan(responseStreamObject)
	destination := make(http.Header)
	err := copySafeResponseHeaders(http.Header{
		"X-Amz-Restore": {`ongoing-request="false", endpoint="ORIGIN.EXAMPLE"`},
		"Content-Type":  {"application/octet-stream"},
	}, destination, config, plan, http.StatusOK)
	require.NoError(t, err)
	assert.Empty(t, destination.Get("X-Amz-Restore"))
	assert.Equal(t, "application/octet-stream", destination.Get("Content-Type"))

	attributes := filterSafeXMLAttributes([]xml.Attr{{Name: xml.Name{Local: "backend"}, Value: "origin.example"}}, config)
	assert.Empty(t, attributes)
}

func TestVirtualResponseLocationPreservesAddressingStyleAndEscapes(t *testing.T) {
	for _, test := range []struct {
		name, key, want string
		vhost           bool
	}{
		{name: "path style", key: "space +%/snowman-\u2603//tail", want: "/virtual-bucket/space%20%2B%25%2Fsnowman-%E2%98%83%2F%2Ftail"},
		{name: "vhost style", key: "space +%/snowman-\u2603//tail", vhost: true, want: "/space%20%2B%25%2Fsnowman-%E2%98%83%2F%2Ftail"},
		{name: "vhost leading slash cannot become authority", key: "/key", vhost: true, want: "/%2Fkey"},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan := responseTestPlan(responseCompleteMultipart)
			plan.objectKey = test.key
			plan.isVHost = test.vhost
			assert.Equal(t, test.want, virtualResponseLocation(plan))
		})
	}
}

func TestResponseXMLValidationAndContainment(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket", nil)
	plan := responseTestPlan(responseListObjects)
	plan.objectKey = ""

	tests := map[string]string{
		"wrong root":        `<Other><Name>real-bucket</Name></Other>`,
		"foreign namespace": `<ListBucketResult xmlns="urn:foreign"><Name>real-bucket</Name></ListBucketResult>`,
		"wrong bucket":      `<ListBucketResult><Name>other-bucket</Name></ListBucketResult>`,
		"foreign key":       `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-b/secret</Key></Contents></ListBucketResult>`,
		"mixed root text":   `<ListBucketResult>real-bucket<Name>real-bucket</Name></ListBucketResult>`,
		"multiple roots":    `<ListBucketResult><Name>real-bucket</Name></ListBucketResult><ListBucketResult/>`,
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
			require.Error(t, err)
			assert.NotContains(t, recorder.Body.String(), "tenant-b/secret")
			if name == "wrong root" || name == "foreign namespace" {
				assert.Equal(t, http.StatusBadGateway, recorder.Code)
			}
		})
	}

	t.Run("split key text transforms atomically", func(t *testing.T) {
		body := `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-<!-- split -->a/secret</Key></Contents></ListBucketResult>`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.NoError(t, err)
		assert.Contains(t, recorder.Body.String(), `<Key>secret</Key>`)
		assert.NotContains(t, recorder.Body.String(), "tenant-a")
	})

	t.Run("truncation after root never emits foreign key", func(t *testing.T) {
		body := `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-b/secret`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.Equal(t, http.StatusOK, recorder.Code, "streaming status is already committed after root preflight")
		assert.NotContains(t, recorder.Body.String(), "tenant-b/secret")
	})

	for name, body := range map[string]string{
		"empty virtual result key":  `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-a/</Key></Contents></ListBucketResult>`,
		"unsafe virtual result key": `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-a/../secret</Key></Contents></ListBucketResult>`,
	} {
		t.Run(name, func(t *testing.T) {
			recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
			require.Error(t, err)
			assert.NotContains(t, recorder.Body.String(), "../secret")
		})
	}

	t.Run("URL-encoded unsafe result key is rejected after decoding", func(t *testing.T) {
		encodedPlan := responseTestPlan(responseListObjects)
		encodedPlan.objectKey = ""
		encodedPlan.query.Set("encoding-type", "url")
		body := `<ListBucketResult><Name>real-bucket</Name><EncodingType>url</EncodingType><Contents><Key>tenant-a%2Fdir%5Csecret</Key></Contents></ListBucketResult>`
		recorder, err := writeResponseForTest(t, request, encodedPlan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.NotContains(t, recorder.Body.String(), "dir%5Csecret")
	})
}

func TestResponseProfilesSynthesizeBackendOwnerAndInitiatorIdentities(t *testing.T) {
	const identitySentinel = "origin-account-id-and-arn-sentinel"
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket", nil)

	listPlan := responseTestPlan(responseListObjects)
	listPlan.objectKey = ""
	listPlan.query.Set("fetch-owner", "true")
	listBody := `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-a/file</Key><Owner><ID>` + identitySentinel + `</ID><DisplayName>` + identitySentinel + `</DisplayName></Owner></Contents></ListBucketResult>`
	listRecorder, err := writeResponseForTest(t, request, listPlan, http.StatusOK, nil, listBody)
	require.NoError(t, err)
	assert.NotContains(t, listRecorder.Body.String(), identitySentinel)
	assert.Contains(t, listRecorder.Body.String(), "<Owner><ID>virtual-bucket</ID><DisplayName>virtual-bucket</DisplayName></Owner>")

	multipartPlan := responseTestPlan(responseListMultipartUploads)
	multipartPlan.objectKey = ""
	multipartBody := `<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><Upload><Key>tenant-a/file</Key><UploadId>origin-upload</UploadId><Owner><ID>` + identitySentinel + `</ID></Owner><Initiator><ID>` + identitySentinel + `</ID></Initiator></Upload></ListMultipartUploadsResult>`
	multipartRecorder, err := writeResponseForTest(t, request, multipartPlan, http.StatusOK, nil, multipartBody)
	require.NoError(t, err)
	assert.NotContains(t, multipartRecorder.Body.String(), identitySentinel)
	assert.Contains(t, multipartRecorder.Body.String(), "<Owner><ID>virtual-bucket</ID><DisplayName>virtual-bucket</DisplayName></Owner>")
	assert.Contains(t, multipartRecorder.Body.String(), "<Initiator><ID>virtual-bucket</ID><DisplayName>virtual-bucket</DisplayName></Initiator>")

	virtualUpload, err := encodeOpaqueToken(responseTestConfig(), "upload", "origin-upload")
	require.NoError(t, err)
	partsPlan := responseTestPlan(responseListParts)
	partsPlan.query.Set("uploadId", virtualUpload)
	partsBody := `<ListPartsResult><Bucket>real-bucket</Bucket><Key>tenant-a/dir/a +%/file.txt</Key><UploadId>origin-upload</UploadId><PartNumberMarker>0</PartNumberMarker><MaxParts>1000</MaxParts><IsTruncated>false</IsTruncated><Owner><ID>` + identitySentinel + `</ID></Owner><Initiator><ID>` + identitySentinel + `</ID></Initiator></ListPartsResult>`
	partsRecorder, err := writeResponseForTest(t, request, partsPlan, http.StatusOK, nil, partsBody)
	require.NoError(t, err)
	assert.NotContains(t, partsRecorder.Body.String(), identitySentinel)
	assert.Contains(t, partsRecorder.Body.String(), "<Owner><ID>virtual-bucket</ID><DisplayName>virtual-bucket</DisplayName></Owner>")
	assert.Contains(t, partsRecorder.Body.String(), "<Initiator><ID>virtual-bucket</ID><DisplayName>virtual-bucket</DisplayName></Initiator>")
}

func TestStreamingResponseRequestEchoesMustMatch(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket", nil)
	for name, test := range map[string]struct {
		profile S3ResponseProfile
		query   url.Values
		body    string
	}{
		"list prefix mismatch": {
			profile: responseListObjects,
			query:   url.Values{"prefix": {"requested/"}},
			body:    `<ListBucketResult><Name>real-bucket</Name><Prefix>tenant-a/other/</Prefix></ListBucketResult>`,
		},
		"list marker without request": {
			profile: responseListObjects,
			query:   make(url.Values),
			body:    `<ListBucketResult><Name>real-bucket</Name><Marker>tenant-a/foreign</Marker></ListBucketResult>`,
		},
		"list delimiter mismatch": {
			profile: responseListObjects,
			query:   url.Values{"delimiter": {"/"}},
			body:    `<ListBucketResult><Name>real-bucket</Name><Delimiter>:</Delimiter></ListBucketResult>`,
		},
		"list encoding type without request": {
			profile: responseListObjects,
			query:   make(url.Values),
			body:    `<ListBucketResult><Name>real-bucket</Name><EncodingType>url</EncodingType></ListBucketResult>`,
		},
		"list max keys mismatch": {
			profile: responseListObjects,
			query:   url.Values{"max-keys": {"10"}},
			body:    `<ListBucketResult><Name>real-bucket</Name><MaxKeys>11</MaxKeys></ListBucketResult>`,
		},
		"multipart key marker mismatch": {
			profile: responseListMultipartUploads,
			query:   url.Values{"key-marker": {"requested"}},
			body:    `<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><KeyMarker>tenant-a/other</KeyMarker></ListMultipartUploadsResult>`,
		},
		"multipart max uploads mismatch": {
			profile: responseListMultipartUploads,
			query:   url.Values{"max-uploads": {"5"}},
			body:    `<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><MaxUploads>6</MaxUploads></ListMultipartUploadsResult>`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			plan := responseTestPlan(test.profile)
			plan.objectKey = ""
			plan.query = test.query
			plan.rawQuery = test.query.Encode()
			recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, test.body)
			require.Error(t, err)
			assert.NotContains(t, recorder.Body.String(), "tenant-a/other")
			assert.NotContains(t, recorder.Body.String(), "tenant-a/foreign")
		})
	}

	t.Run("fetch owner requires an owner per listed object", func(t *testing.T) {
		plan := responseTestPlan(responseListObjects)
		plan.objectKey = ""
		plan.query.Set("fetch-owner", "true")
		body := `<ListBucketResult><Name>real-bucket</Name><Contents><Key>tenant-a/file</Key></Contents></ListBucketResult>`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.NotContains(t, recorder.Body.String(), "origin-account")
	})
}

func TestListMultipartUploadsAcceptsOfficialEmptyMarkerShape(t *testing.T) {
	plan := responseTestPlan(responseListMultipartUploads)
	plan.objectKey = ""
	body := `<ListMultipartUploadsResult>` +
		`<Bucket>real-bucket</Bucket>` +
		`<KeyMarker></KeyMarker><UploadIdMarker/>` +
		`<NextKeyMarker/><NextUploadIdMarker></NextUploadIdMarker>` +
		`<Prefix>tenant-a/</Prefix><MaxUploads>1000</MaxUploads><IsTruncated>false</IsTruncated>` +
		`</ListMultipartUploadsResult>`
	recorder, err := writeResponseForTest(t, httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket?uploads", nil), plan, http.StatusOK, nil, body)
	require.NoError(t, err)
	assert.Contains(t, recorder.Body.String(), `<Bucket>virtual-bucket</Bucket>`)
	assert.Contains(t, recorder.Body.String(), `<KeyMarker></KeyMarker>`)
	assert.Contains(t, recorder.Body.String(), `<UploadIdMarker></UploadIdMarker>`)
	assert.Contains(t, recorder.Body.String(), `<NextKeyMarker></NextKeyMarker>`)
	assert.Contains(t, recorder.Body.String(), `<NextUploadIdMarker></NextUploadIdMarker>`)
	assert.Contains(t, recorder.Body.String(), `<Prefix></Prefix>`)
}

func TestListTokenEmptyValuesRemainPathSpecific(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket", nil)

	t.Run("nonempty upload marker without request is rejected", func(t *testing.T) {
		plan := responseTestPlan(responseListMultipartUploads)
		plan.objectKey = ""
		body := `<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><UploadIdMarker>origin-marker</UploadIdMarker></ListMultipartUploadsResult>`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.NotContains(t, recorder.Body.String(), "origin-marker")
	})

	t.Run("empty actual upload ID remains invalid", func(t *testing.T) {
		plan := responseTestPlan(responseListMultipartUploads)
		plan.objectKey = ""
		body := `<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><Upload><Key>tenant-a/file</Key><UploadId/></Upload></ListMultipartUploadsResult>`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.Error(t, err)
		assert.NotContains(t, recorder.Body.String(), "vb1.upload")
	})

	t.Run("empty next upload marker requires nontruncated response", func(t *testing.T) {
		plan := responseTestPlan(responseListMultipartUploads)
		plan.objectKey = ""
		body := `<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><NextUploadIdMarker/><IsTruncated>true</IsTruncated></ListMultipartUploadsResult>`
		_, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.Error(t, err)
	})

	t.Run("empty continuation fields are valid only without a request or truncation", func(t *testing.T) {
		plan := responseTestPlan(responseListObjects)
		plan.objectKey = ""
		body := `<ListBucketResult><Name>real-bucket</Name><ContinuationToken/><NextContinuationToken/><IsTruncated>false</IsTruncated></ListBucketResult>`
		recorder, err := writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.NoError(t, err)
		assert.Contains(t, recorder.Body.String(), `<ContinuationToken></ContinuationToken>`)
		assert.Contains(t, recorder.Body.String(), `<NextContinuationToken></NextContinuationToken>`)

		body = `<ListBucketResult><Name>real-bucket</Name><NextContinuationToken/><IsTruncated>true</IsTruncated></ListBucketResult>`
		_, err = writeResponseForTest(t, request, plan, http.StatusOK, nil, body)
		require.Error(t, err)
	})
}

func TestOpaqueResponseTokensEchoAndRoundTrip(t *testing.T) {
	config := responseTestConfig()
	virtualContinuation, err := encodeOpaqueToken(config, "continuation", "origin-current")
	require.NoError(t, err)
	plan := responseTestPlan(responseListObjects)
	plan.objectKey = ""
	plan.query.Set("continuation-token", virtualContinuation)
	plan.rawQuery = "list-type=2&continuation-token=" + url.QueryEscape(virtualContinuation)
	body := `<ListBucketResult><Name>real-bucket</Name><ContinuationToken>origin-current</ContinuationToken><NextContinuationToken>origin-next</NextContinuationToken></ListBucketResult>`
	recorder, err := writeResponseForTest(t, httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket?"+plan.rawQuery, nil), plan, http.StatusOK, nil, body)
	require.NoError(t, err)
	assert.Contains(t, recorder.Body.String(), `<ContinuationToken>`+virtualContinuation+`</ContinuationToken>`)
	next := between(recorder.Body.String(), "<NextContinuationToken>", "</NextContinuationToken>")
	require.NotEmpty(t, next)
	decoded, err := decodeOpaqueToken(config, "continuation", next)
	require.NoError(t, err)
	assert.Equal(t, "origin-next", decoded)

	rewritten, err := rewriteOutboundQuery(operationListObjectsV2, "list-type=2&continuation-token="+url.QueryEscape(next), "tenant-a/", true, config)
	require.NoError(t, err)
	query, err := url.ParseQuery(rewritten)
	require.NoError(t, err)
	assert.Equal(t, "origin-next", query.Get("continuation-token"))

	missingPlan := responseTestPlan(responseListObjects)
	missingPlan.objectKey = ""
	for name, test := range map[string]struct {
		plan *S3OperationPlan
		body string
	}{
		"mismatched echo": {plan: plan, body: `<ListBucketResult><Name>real-bucket</Name><ContinuationToken>wrong-origin</ContinuationToken></ListBucketResult>`},
		"absent request":  {plan: missingPlan, body: `<ListBucketResult><Name>real-bucket</Name><ContinuationToken>origin-current</ContinuationToken></ListBucketResult>`},
	} {
		t.Run(name, func(t *testing.T) {
			recorder, err := writeResponseForTest(t, httptest.NewRequest(http.MethodGet, "http://proxy.example/virtual-bucket", nil), test.plan, http.StatusOK, nil, test.body)
			require.Error(t, err)
			assert.NotContains(t, recorder.Body.String(), "wrong-origin")
			assert.NotContains(t, recorder.Body.String(), "origin-current")
		})
	}
}

func between(value, start, end string) string {
	startIndex := strings.Index(value, start)
	if startIndex < 0 {
		return ""
	}
	remainder := value[startIndex+len(start):]
	endIndex := strings.Index(remainder, end)
	if endIndex < 0 {
		return ""
	}
	return remainder[:endIndex]
}

type failAfterWriter struct {
	remaining int
}

func (w *failAfterWriter) Write(data []byte) (int, error) {
	if w.remaining <= 0 {
		return 0, errors.New("client canceled")
	}
	if len(data) > w.remaining {
		data = data[:w.remaining]
	}
	w.remaining -= len(data)
	return len(data), nil
}

func TestStreamingRewritePropagatesWriterCancellation(t *testing.T) {
	plan := responseTestPlan(responseListObjects)
	plan.objectKey = ""
	body := `<ListBucketResult><Name>real-bucket</Name>` + strings.Repeat(`<Contents><Key>tenant-a/file</Key></Contents>`, 100) + `</ListBucketResult>`
	err := rewriteStreamingNamespaceResponse(strings.NewReader(body), &failAfterWriter{remaining: 64}, plan, responseTestConfig(), "tenant-a/")
	require.Error(t, err)
}

func BenchmarkStreamingListNamespaceRewrite(b *testing.B) {
	plan := responseTestPlan(responseListObjects)
	plan.objectKey = ""
	body := []byte(`<ListBucketResult><Name>real-bucket</Name>` + strings.Repeat(`<Contents><Key>tenant-a/file</Key></Contents>`, 1000) + `</ListBucketResult>`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		if err := rewriteStreamingNamespaceResponse(bytes.NewReader(body), io.Discard, plan, responseTestConfig(), "tenant-a/"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamingURLEncodedListNamespaceRewrite(b *testing.B) {
	plan := responseTestPlan(responseListObjects)
	plan.objectKey = ""
	plan.query.Set("encoding-type", "url")
	body := []byte(`<ListBucketResult><Name>real-bucket</Name><EncodingType>url</EncodingType>` + strings.Repeat(`<Contents><Key>tenant-a%2Ffile%20name</Key></Contents>`, 1000) + `</ListBucketResult>`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for i := 0; i < b.N; i++ {
		if err := rewriteStreamingNamespaceResponse(bytes.NewReader(body), io.Discard, plan, responseTestConfig(), "tenant-a/"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMultipartUploadTokenTransform(b *testing.B) {
	plan := responseTestPlan(responseListMultipartUploads)
	plan.objectKey = ""
	var body strings.Builder
	body.WriteString(`<ListMultipartUploadsResult><Bucket>real-bucket</Bucket><Prefix>tenant-a/</Prefix>`)
	for i := 0; i < 1000; i++ {
		body.WriteString(`<Upload><Key>tenant-a/file</Key><UploadId>origin-upload-`)
		body.WriteString(strconv.Itoa(i))
		body.WriteString(`</UploadId></Upload>`)
	}
	body.WriteString(`</ListMultipartUploadsResult>`)
	bodyBytes := []byte(body.String())

	for _, test := range []struct {
		name       string
		normalized bool
	}{
		{name: "rebuild-codec-per-field"},
		{name: "reuse-request-codec", normalized: true},
	} {
		b.Run(test.name, func(b *testing.B) {
			config := responseTestConfig()
			if test.normalized {
				var err error
				config, err = NormalizeVBucketConfig(config)
				if err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(bodyBytes)))
			for i := 0; i < b.N; i++ {
				if err := rewriteStreamingNamespaceResponse(bytes.NewReader(bodyBytes), io.Discard, plan, config, "tenant-a/"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
