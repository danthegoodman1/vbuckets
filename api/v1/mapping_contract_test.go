package apiv1

import (
	"os"
	"strings"
	"testing"
)

func TestControlPlaneMappingContractDocumentsIsolationAndStableRoutingKeys(t *testing.T) {
	proto, err := os.ReadFile("controlplane.proto")
	if err != nil {
		t.Fatal(err)
	}
	contract := string(proto)
	for _, guarantee := range []string{
		"pairwise\n  // non-overlapping",
		"empty prefix reserves the whole real bucket exclusively",
		"stable 32-byte random key",
		"MUST generate a new key",
		"whenever real_endpoint, real_bucket, or path_prefix changes",
		"invalidates outstanding virtual continuation",
	} {
		if !strings.Contains(contract, guarantee) {
			t.Fatalf("control-plane mapping contract is missing %q", guarantee)
		}
	}
}
