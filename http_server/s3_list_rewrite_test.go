package http_server

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRewriteListResponse_StreamRewritesExpectedFields(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>real-bucket</Name>
  <Prefix>tenant-abc/dir/</Prefix>
  <StartAfter>tenant-abc/aa</StartAfter>
  <Marker>tenant-abc/mm</Marker>
  <NextMarker>tenant-abc/nn</NextMarker>
  <Contents><Key>tenant-abc/dir/a.txt</Key></Contents>
  <CommonPrefixes><Prefix>tenant-abc/dir/sub/</Prefix></CommonPrefixes>
</ListBucketResult>`

	var output bytes.Buffer
	err := rewriteListResponseForTest(strings.NewReader(input), &output, false)
	require.NoError(t, err)

	got := output.String()
	assert.Contains(t, got, "<Name>virtual-bucket</Name>")
	assert.Contains(t, got, "<Prefix>dir/</Prefix>")
	assert.Contains(t, got, "<StartAfter>aa</StartAfter>")
	assert.Contains(t, got, "<Marker>mm</Marker>")
	assert.Contains(t, got, "<NextMarker>nn</NextMarker>")
	assert.Contains(t, got, "<Key>dir/a.txt</Key>")
	assert.Contains(t, got, "<Prefix>dir/sub/</Prefix>")
	assert.NotContains(t, got, "tenant-abc/")
}

func TestRewriteListResponse_StreamHandlesLargeBody(t *testing.T) {
	var input strings.Builder
	input.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>real-bucket</Name>`)
	for i := 0; i < 2500; i++ {
		input.WriteString(fmt.Sprintf("<Contents><Key>tenant-abc/file-%04d.txt</Key></Contents>", i))
	}
	input.WriteString(`</ListBucketResult>`)

	var output bytes.Buffer
	err := rewriteListResponseForTest(strings.NewReader(input.String()), &output, false)
	require.NoError(t, err)

	got := output.String()
	assert.Contains(t, got, "<Name>virtual-bucket</Name>")
	assert.Contains(t, got, "<Key>file-2499.txt</Key>")
	assert.NotContains(t, got, "tenant-abc/file-")
}

func TestRewriteListResponse_StreamRewritesURLEncodedFields(t *testing.T) {
	input := `<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <Name>real-bucket</Name>
  <EncodingType>url</EncodingType>
  <Prefix>tenant-abc%2Fdir%2F</Prefix>
  <StartAfter>tenant-abc%2Faa%20one</StartAfter>
  <Marker>tenant-abc%2Fmm%2Bplus</Marker>
  <NextMarker>tenant-abc%2Fnn%2Fnext</NextMarker>
  <Contents><Key>tenant-abc%2Fdir%2Fa%20file.txt</Key></Contents>
  <CommonPrefixes><Prefix>tenant-abc%2Fdir%2Fsub%2F</Prefix></CommonPrefixes>
</ListBucketResult>`

	var output bytes.Buffer
	err := rewriteListResponseForTest(strings.NewReader(input), &output, true)
	require.NoError(t, err)

	got := output.String()
	assert.Contains(t, got, "<Name>virtual-bucket</Name>")
	assert.Contains(t, got, "<EncodingType>url</EncodingType>")
	assert.Contains(t, got, "<Prefix>dir%2F</Prefix>")
	assert.Contains(t, got, "<StartAfter>aa%20one</StartAfter>")
	assert.Contains(t, got, "<Marker>mm%2Bplus</Marker>")
	assert.Contains(t, got, "<NextMarker>nn%2Fnext</NextMarker>")
	assert.Contains(t, got, "<Key>dir%2Fa%20file.txt</Key>")
	assert.Contains(t, got, "<Prefix>dir%2Fsub%2F</Prefix>")
	assert.NotContains(t, got, "tenant-abc")
}

func rewriteListResponseForTest(input *strings.Reader, output *bytes.Buffer, urlEncoded bool) error {
	plan := &S3OperationPlan{
		bucket: "virtual-bucket", responseProfile: responseListObjects,
		query: make(map[string][]string), forwardHeaders: make(map[string][]string),
	}
	plan.query.Set("prefix", "dir/")
	plan.query.Set("start-after", "aa")
	plan.query.Set("marker", "mm")
	if urlEncoded {
		plan.rawQuery = "encoding-type=url"
		plan.query.Set("encoding-type", "url")
		plan.query.Set("start-after", "aa one")
		plan.query.Set("marker", "mm+plus")
	}
	config := &VBucketConfig{RealBucket: "real-bucket", PathPrefix: "tenant-abc", RoutingTokenKey: testRoutingTokenKey}
	return rewriteStreamingNamespaceResponse(input, output, plan, config, "tenant-abc/")
}
