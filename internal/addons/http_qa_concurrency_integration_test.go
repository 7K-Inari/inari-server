//go:build integration

// Concurrency probe: simultaneous adopts of the same catalog item on the
// same cluster must not double-register. Exactly one call may win; the
// others must get 409 (ErrAlreadyManaged), and the stored row's ID must
// match the ArgoCD app name that was registered (status folding keys off
// the app name).
package addons_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

// rowID reads the persisted addon row's ID straight from the DB.
func (f *itFixture) rowID(t *testing.T, orgID, clusterID, item string) string {
	t.Helper()
	var id string
	err := f.database.Pool.QueryRow(t.Context(),
		`SELECT id FROM cluster_addons WHERE org_id=$1 AND cluster_id=$2 AND catalog_item=$3`,
		orgID, clusterID, item).Scan(&id)
	if err != nil {
		return ""
	}
	return id
}

func TestQAConcurrentAdopts(t *testing.T) {
	f := newITServer(t, types.CommitPolicyDirect)
	defer f.srv.Close()
	path := "/api/v1/tenants/acme/clusters/cluster-1/addons/platform:cert-manager/adopt"

	const n = 4
	codes := make([]int, n)
	ids := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			code, body := f.req(t, http.MethodPost, path, "admin", `{"version":"v1.16.1"}`)
			codes[i] = code
			if code == http.StatusOK {
				var out struct {
					Addon struct {
						ID string `json:"id"`
					} `json:"addon"`
				}
				if json.Unmarshal([]byte(body), &out) == nil {
					ids[i] = out.Addon.ID
				}
			}
		}(i)
	}
	wg.Wait()

	wins := 0
	winID := ""
	for i := range codes {
		if codes[i] == http.StatusOK {
			wins++
			winID = ids[i]
		} else if codes[i] != http.StatusConflict {
			t.Errorf("adopt %d: got %d, want 200 or 409", i, codes[i])
		}
	}
	if wins != 1 {
		t.Errorf("concurrent adopts: %d winners, want exactly 1 (codes %v)", wins, codes)
	}

	// The persisted row must be the one whose registration was enqueued:
	// its ID appears in the ArgoCD app name, and a follow-up PATCH by that
	// ID must not 404.
	rowID := f.rowID(t, "org:1", "cluster-1", "platform:cert-manager")
	if rowID == "" {
		t.Fatal("no managed row persisted")
	}
	if len(f.queue.cmds) == 0 {
		t.Fatal("no registration command enqueued")
	}
	for _, c := range f.queue.cmds {
		// The on-cluster name lowercases the ULID (RFC 1123).
		if !strings.Contains(string(c.Payload), strings.ToLower(rowID)) {
			t.Errorf("registered command does not reference the persisted row %s: %s", rowID, c.Payload)
		}
	}
	if winID != "" && winID != rowID {
		t.Errorf("winning response ID %s != persisted row ID %s", winID, rowID)
	}
	if code, body := f.req(t, http.MethodPatch, "/api/v1/tenants/acme/addons/"+rowID, "admin",
		`{"chartVersion":"v1.16.2"}`); code != http.StatusOK {
		t.Errorf("patch persisted row: got %d (%s), want 200", code, body)
	}
}
