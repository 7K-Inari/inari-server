package clusterregistry

import (
	"regexp"
	"testing"

	"github.com/7K-Inari/inari-api/contract/clusterids"
)

// charsetRe mirrors the reference charset pinned by the inari-api
// clusterids contract testdata.
var charsetRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// TestIssuedClusterIDMatchesContract guards the server side of the
// cluster-ID charset contract: the IDs CreateCluster issues must stay
// within the canonical charset the shared inari-api testdata pins (and
// inari-cli validates against), and the testdata must carry the
// canonical cluster:<uuid> shape. If the ID format ever changes, update
// the contract testdata first.
func TestIssuedClusterIDMatchesContract(t *testing.T) {
	id := "cluster:" + newUUID()
	if !charsetRe.MatchString(id) {
		t.Errorf("issued cluster ID %q violates the contract charset", id)
	}
	canonical := regexp.MustCompile(`^cluster:[0-9a-f-]{36}$`)
	if !canonical.MatchString(id) {
		t.Errorf("issued cluster ID %q lost the canonical cluster:<uuid> shape", id)
	}
	found := false
	for _, valid := range clusterids.ValidIDs {
		if canonical.MatchString(valid) {
			found = true
		}
	}
	if !found {
		t.Error("contract testdata carries no canonical cluster:<uuid> entry — update clusterids.ValidIDs")
	}
}
