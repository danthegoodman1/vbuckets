package apiv1_test

import (
	"reflect"
	"testing"

	apiv1 "github.com/danthegoodman1/vbuckets/api/v1"
	"google.golang.org/protobuf/types/descriptorpb"
)

const canonicalGoPackage = "github.com/danthegoodman1/vbuckets/api/v1"

// TestGeneratedGoPackageMatchesCanonicalImportPath prevents generated files
// from drifting away from the go_package declared by controlplane.proto.
func TestGeneratedGoPackageMatchesCanonicalImportPath(t *testing.T) {
	generatedTypePackage := reflect.TypeOf(apiv1.LookupCredentialsRequest{}).PkgPath()
	descriptorPackage := string(apiv1.File_v1_controlplane_proto.Options().(*descriptorpb.FileOptions).GetGoPackage())

	if generatedTypePackage != canonicalGoPackage {
		t.Errorf("generated Go type package = %q, want %q", generatedTypePackage, canonicalGoPackage)
	}
	if descriptorPackage != canonicalGoPackage+";apiv1" {
		t.Errorf("protobuf go_package = %q, want %q", descriptorPackage, canonicalGoPackage+";apiv1")
	}
}
