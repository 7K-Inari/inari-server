//go:build integration

package approvals

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/types"
)

func itPut(t *testing.T, srv *httptest.Server, path, token string, body any) (int, string) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPut, srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	_, _ = io.Copy(&sb, resp.Body)
	return resp.StatusCode, sb.String()
}

func decodeConfig(t *testing.T, body string) types.ApprovalConfigRecord {
	t.Helper()
	var out types.ApprovalConfigRecord
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	return out
}

// TestGetApprovalConfigDefaults covers GET with no stored row: effective
// defaults with null updatedAt, plus the auth matrix.
func TestGetApprovalConfigDefaults(t *testing.T) {
	srv, _ := itServer(t, allowAll())
	defer srv.Close()

	code, body := itReq(t, srv, "/api/v1/tenants/acme/approval-config", "good")
	if code != http.StatusOK {
		t.Fatalf("GET: %d %s", code, body)
	}
	rec := decodeConfig(t, body)
	if rec.OrgID != "org:1" {
		t.Errorf("orgId = %q, want org:1", rec.OrgID)
	}
	if rec.UpdatedAt != nil {
		t.Errorf("updatedAt = %v, want null for defaults", rec.UpdatedAt)
	}
	if rec.Config.DefaultPolicy != types.ApprovalPolicyAuto {
		t.Errorf("defaultPolicy = %q, want auto", rec.Config.DefaultPolicy)
	}
	if rec.Config.ApprovalTTL != DefaultTTL.String() {
		t.Errorf("approvalTtl = %q, want %q", rec.Config.ApprovalTTL, DefaultTTL.String())
	}

	// Auth matrix: non-member and denied authorizer are forbidden; no token 401.
	if code, _ := itReq(t, srv, "/api/v1/tenants/acme/approval-config", "outsider"); code != http.StatusForbidden {
		t.Errorf("outsider GET: got %d, want 403", code)
	}
	if code, _ := itReq(t, srv, "/api/v1/tenants/acme/approval-config", ""); code != http.StatusUnauthorized {
		t.Errorf("no token GET: got %d, want 401", code)
	}
	srvDeny, _ := itServer(t, itAuthorizer{allow: map[string]bool{}})
	defer srvDeny.Close()
	if code, _ := itReq(t, srvDeny, "/api/v1/tenants/acme/approval-config", "good"); code != http.StatusForbidden {
		t.Errorf("denied GET: got %d, want 403", code)
	}
}

// TestUpdateApprovalConfigRoundTrip covers PUT -> GET persistence, audit
// row with before/after payload, outbox event, and 422 on invalid config.
func TestUpdateApprovalConfigRoundTrip(t *testing.T) {
	srv, database := itServer(t, allowAll())
	defer srv.Close()
	ctx := context.Background()

	put := map[string]any{
		"config": map[string]any{
			"defaultPolicy":  "peer",
			"approvalTtl":    "48h",
			"thresholds":     []any{map[string]any{"kind": "cost", "gt": 1000, "policy": "platform-admin"}},
			"approverGroups": []any{map[string]any{"name": "sre", "subjects": []any{"user:a"}}},
			"autoApprove":    []any{map[string]any{"kind": "catalog_item", "itemIds": []any{"item-1"}}},
		},
	}
	code, body := itPut(t, srv, "/api/v1/tenants/acme/approval-config", "good", put)
	if code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, body)
	}
	rec := decodeConfig(t, body)
	if rec.UpdatedAt == nil {
		t.Error("PUT response updatedAt must be set")
	}
	if rec.Config.DefaultPolicy != types.ApprovalPolicyPeer || rec.Config.ApprovalTTL != "48h" {
		t.Errorf("PUT response config = %+v", rec.Config)
	}
	if len(rec.Config.Thresholds) != 1 || rec.Config.Thresholds[0].Policy != types.ApprovalPolicyPlatformAdmin {
		t.Errorf("thresholds = %+v", rec.Config.Thresholds)
	}

	// GET round-trip returns the stored config.
	code, body = itReq(t, srv, "/api/v1/tenants/acme/approval-config", "good")
	if code != http.StatusOK {
		t.Fatalf("GET after PUT: %d %s", code, body)
	}
	got := decodeConfig(t, body)
	if got.Config.DefaultPolicy != types.ApprovalPolicyPeer || got.UpdatedAt == nil {
		t.Errorf("GET after PUT = %+v", got)
	}

	// Audit row: approvals.config.updated with before (defaults) / after.
	var action string
	var payload []byte
	err := database.Pool.QueryRow(ctx,
		`SELECT action, payload FROM audit_events WHERE org_id = 'org:1' AND object_type = 'approval_config'`,
	).Scan(&action, &payload)
	if err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if action != types.EventApprovalConfigUpdated {
		t.Errorf("audit action = %q, want %q", action, types.EventApprovalConfigUpdated)
	}
	var ap types.ApprovalConfigPayload
	if err := json.Unmarshal(payload, &ap); err != nil {
		t.Fatal(err)
	}
	if ap.Before == nil || ap.Before.DefaultPolicy != types.ApprovalPolicyAuto {
		t.Errorf("before = %+v, want defaults", ap.Before)
	}
	if ap.After == nil || ap.After.DefaultPolicy != types.ApprovalPolicyPeer {
		t.Errorf("after = %+v, want peer config", ap.After)
	}

	// Outbox row for the same event.
	var eventType string
	err = database.Pool.QueryRow(ctx,
		`SELECT event_type FROM outbox WHERE org_id = 'org:1' AND event_type = $1`,
		types.EventApprovalConfigUpdated).Scan(&eventType)
	if err != nil {
		t.Fatalf("outbox row: %v", err)
	}

	// Second PUT: before reflects the first stored config.
	put["config"].(map[string]any)["defaultPolicy"] = "platform-admin"
	code, body = itPut(t, srv, "/api/v1/tenants/acme/approval-config", "good", put)
	if code != http.StatusOK {
		t.Fatalf("second PUT: %d %s", code, body)
	}
	err = database.Pool.QueryRow(ctx,
		`SELECT payload FROM audit_events WHERE org_id = 'org:1' AND object_type = 'approval_config'
		 ORDER BY created_at DESC LIMIT 1`).Scan(&payload)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &ap); err != nil {
		t.Fatal(err)
	}
	if ap.Before.DefaultPolicy != types.ApprovalPolicyPeer {
		t.Errorf("second before = %q, want peer", ap.Before.DefaultPolicy)
	}
	if ap.After.DefaultPolicy != types.ApprovalPolicyPlatformAdmin {
		t.Errorf("second after = %q, want platform-admin", ap.After.DefaultPolicy)
	}

	// Invalid config is rejected with 422 and writes nothing.
	bad := map[string]any{"config": map[string]any{"defaultPolicy": "magic", "approvalTtl": "48h"}}
	code, body = itPut(t, srv, "/api/v1/tenants/acme/approval-config", "good", bad)
	if code != http.StatusUnprocessableEntity {
		t.Errorf("invalid PUT: got %d %s, want 422", code, body)
	}
	var n int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE org_id = 'org:1' AND object_type = 'approval_config'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("audit rows = %d, want 2 (invalid PUT must not write)", n)
	}
}

// TestUpdateApprovalConfigAuthz covers write-side auth: non-member 403,
// authorizer-denied 403, unauthenticated 401.
func TestUpdateApprovalConfigAuthz(t *testing.T) {
	put := map[string]any{"config": map[string]any{"defaultPolicy": "peer", "approvalTtl": "48h"}}

	srv, _ := itServer(t, allowAll())
	defer srv.Close()
	if code, body := itPut(t, srv, "/api/v1/tenants/acme/approval-config", "outsider", put); code != http.StatusForbidden {
		t.Errorf("outsider PUT: got %d %s, want 403", code, body)
	}
	if code, _ := itPut(t, srv, "/api/v1/tenants/acme/approval-config", "", put); code != http.StatusUnauthorized {
		t.Errorf("no token PUT: got %d, want 401", code)
	}

	// Authorizer denies platform_engineer (viewer-only principal).
	srvDeny, _ := itServer(t, itAuthorizer{allow: map[string]bool{}})
	defer srvDeny.Close()
	if code, _ := itPut(t, srvDeny, "/api/v1/tenants/acme/approval-config", "good", put); code != http.StatusForbidden {
		t.Errorf("denied PUT: got %d, want 403", code)
	}
}

// TestApprovalConfigUnknownOrg maps tenancy resolution failure to 404.
func TestApprovalConfigUnknownOrg(t *testing.T) {
	srv, _ := itServer(t, allowAll())
	defer srv.Close()
	// "ghost" is in the drifter token but not resolvable by itTenants.
	if code, _ := itReq(t, srv, "/api/v1/tenants/ghost/approval-config", "drifter"); code != http.StatusNotFound {
		t.Errorf("unknown org GET: got %d, want 404", code)
	}
}
