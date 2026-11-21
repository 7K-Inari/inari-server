package deploymentplan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/authz"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type qaHTTPValidator struct{}

func (qaHTTPValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	switch raw {
	case "good":
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	case "outsider":
		return &authn.Identity{Subject: "user-2", Organizations: []string{"other"}}, nil
	default:
		return nil, errors.New("invalid token")
	}
}

type qaHTTPReady struct{}

func (qaHTTPReady) Ping(context.Context) error { return nil }

type qaHTTPTenants map[string]*types.Organization

func (t qaHTTPTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if org := t[slug]; org != nil {
		return org, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

type qaHTTPAuthorizer struct {
	defaultAllow bool
	allowed      map[string]bool
	err          error
}

func (a *qaHTTPAuthorizer) Check(_ context.Context, _, relation, _ string) (bool, error) {
	if a.err != nil {
		return false, a.err
	}
	if allowed, ok := a.allowed[relation]; ok {
		return allowed, nil
	}
	return a.defaultAllow, nil
}

func (a *qaHTTPAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type qaHTTPRepoWrite struct {
	err         error
	repoIDs     []string
	instanceIDs []string
}

func (r *qaHTTPRepoWrite) EnforceRepoWrite(_ context.Context, _ *authn.Identity, _, repoID string) error {
	r.repoIDs = append(r.repoIDs, repoID)
	return r.err
}

func (r *qaHTTPRepoWrite) EnforceRecordedRepoWrite(_ context.Context, _ *authn.Identity, _, instanceID string) error {
	r.instanceIDs = append(r.instanceIDs, instanceID)
	return r.err
}

func newQAHTTPServer(t *testing.T, svc *Service, az *qaHTTPAuthorizer, repoWrite *qaHTTPRepoWrite) *httptest.Server {
	t.Helper()
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)), qaHTTPValidator{}, qaHTTPReady{})
	tenants := qaHTTPTenants{"acme": {ID: "org-1", Slug: "acme-inc", Status: types.OrgStatusActive}}
	NewHandler(svc, tenants, az).WithRepoWriteEnforcement(repoWrite).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)
	return srv
}

func qaHTTPJSON(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = strings.NewReader(string(raw))
	}
	req, err := http.NewRequest(method, srv.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func qaHTTPPreflight(t *testing.T, srv *httptest.Server, request PlanRequest) Preflight {
	t.Helper()
	code, raw := qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans/preflight", "good", request)
	if code != http.StatusOK {
		t.Fatalf("preflight = %d %s", code, raw)
	}
	var out struct {
		Preflight Preflight `json:"preflight"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Preflight
}

func qaHTTPSubmitRequest(preflight Preflight, idempotencyKey string) PlanRequest {
	source := preflight.Plan.Source
	return PlanRequest{
		Operation: preflight.Plan.Operation, InstanceID: preflight.Plan.AppInstanceID, Source: &source,
		Deployment: preflight.Plan.Deployment, Observability: preflight.Plan.Observability,
		PlanFingerprint: preflight.Plan.PlanFingerprint, IdempotencyKey: idempotencyKey,
	}
}

func qaHTTPSubmit(t *testing.T, srv *httptest.Server, request PlanRequest) Plan {
	t.Helper()
	code, raw := qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans", "good", request)
	if code != http.StatusOK {
		t.Fatalf("submit = %d %s", code, raw)
	}
	var out struct {
		Plan Plan `json:"plan"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out.Plan
}

func TestQAHTTPAllSourcesPreflightSubmitAndRead(t *testing.T) {
	for _, kind := range []SourceKind{SourceCatalog, SourceChart, SourceTemplate} {
		t.Run(string(kind), func(t *testing.T) {
			svc, cat, _, _, _ := serviceFixture(t)
			request := deployRequest()
			switch kind {
			case SourceChart:
				request.Source = &Source{Kind: SourceChart, SourceID: "hiroba", Ref: "oci://ghcr.io/7k-hiroba/payments-api/charts/payments-api", Version: "1.4.0", Digest: testDigest}
			case SourceTemplate:
				payload, _ := json.Marshal(map[string]any{"manifest": map[string]any{"kind": "component", "observability": map[string]any{"manifest": "observability/observability.yaml"}}, "observabilityYaml": capabilityYAML(t)})
				cat.version.Payload = payload
				cat.version.ChartRef, cat.version.ChartDigest = "", ""
				request.Source = &Source{Kind: SourceTemplate, ItemID: cat.item.ID, Version: "1.4.0", DisplayName: "payments"}
			}
			srv := newQAHTTPServer(t, svc, &qaHTTPAuthorizer{defaultAllow: true}, &qaHTTPRepoWrite{})
			preflight := qaHTTPPreflight(t, srv, request)
			if preflight.Plan.Capability == nil || preflight.Plan.App.Digest != testDigest || preflight.Plan.Source.Kind != kind {
				t.Fatalf("normalized preflight = %#v", preflight.Plan)
			}
			if preflight.Plan.Gate.CompanionRendering || preflight.Plan.Gate.DeployedVerification || len(preflight.CompatiblePacks) != 1 || len(preflight.MonitoringTargets) != 1 {
				t.Fatalf("preflight gate/compatibility = %#v", preflight)
			}
			plan := qaHTTPSubmit(t, srv, qaHTTPSubmitRequest(preflight, request.IdempotencyKey))
			if plan.Companion == nil || plan.Companion.State != "blocked_external_gate" || len(plan.Companion.Links) != 0 {
				t.Fatalf("submitted companion = %#v", plan.Companion)
			}
			if kind == SourceTemplate && plan.ScaffoldRunID == "" {
				t.Fatalf("template execution = %#v", plan)
			}
			if kind != SourceTemplate && plan.AppInstanceID == "" {
				t.Fatalf("application execution = %#v", plan)
			}
			code, raw := qaHTTPJSON(t, srv, http.MethodGet, "/api/v1/tenants/acme/deployment-plans/"+plan.ID, "good", nil)
			if code != http.StatusOK || !strings.Contains(string(raw), `"id":"`+plan.ID+`"`) {
				t.Fatalf("get plan = %d %s", code, raw)
			}
			if kind != SourceTemplate {
				code, raw = qaHTTPJSON(t, srv, http.MethodGet, "/api/v1/tenants/acme/instances/"+plan.AppInstanceID+"/observability", "good", nil)
				if code != http.StatusOK || !strings.Contains(string(raw), `"state":"blocked_external_gate"`) || strings.Contains(string(raw), `"url":`) {
					t.Fatalf("instance observability = %d %s", code, raw)
				}
			}
		})
	}
}

func TestQAHTTPAuthenticationAndAuthorization(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	az := &qaHTTPAuthorizer{defaultAllow: true}
	srv := newQAHTTPServer(t, svc, az, &qaHTTPRepoWrite{})
	request := deployRequest()
	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{name: "missing token", want: http.StatusUnauthorized},
		{name: "invalid token", token: "bad", want: http.StatusUnauthorized},
		{name: "wrong organization", token: "outsider", want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans/preflight", tc.token, request)
			if code != tc.want {
				t.Fatalf("preflight = %d, want %d", code, tc.want)
			}
		})
	}
	az.defaultAllow = false
	code, _ := qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans/preflight", "good", request)
	if code != http.StatusForbidden {
		t.Fatalf("preflight without deployments.create = %d, want 403", code)
	}
	az.err = errors.New("authorization unavailable")
	code, _ = qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans/preflight", "good", request)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("preflight with authorization outage = %d, want 503", code)
	}
}

func TestQAHTTPReadStatusDoesNotRequireDeploymentsCreate(t *testing.T) {
	svc, _, _, executor, _ := serviceFixture(t)
	az := &qaHTTPAuthorizer{defaultAllow: true}
	srv := newQAHTTPServer(t, svc, az, &qaHTTPRepoWrite{})
	request := deployRequest()
	request.Observability.Mode = ModeSkip
	initial := qaHTTPPreflight(t, srv, request)
	plan := qaHTTPSubmit(t, srv, qaHTTPSubmitRequest(initial, request.IdempotencyKey))

	az.defaultAllow = false
	az.allowed = map[string]bool{authz.RelationTenantRead: true, authz.RelationDeploymentsCreate: false}
	for _, path := range []string{
		"/api/v1/tenants/acme/deployment-plans/" + plan.ID,
		"/api/v1/tenants/acme/instances/" + plan.AppInstanceID + "/observability",
	} {
		code, raw := qaHTTPJSON(t, srv, http.MethodGet, path, "good", nil)
		if code != http.StatusOK {
			t.Fatalf("read %s = %d %s", path, code, raw)
		}
	}
	code, _ := qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans/preflight", "good", request)
	if code != http.StatusForbidden || executor.calls != 1 {
		t.Fatalf("read-only preflight = %d, executions %d", code, executor.calls)
	}
	az.allowed[authz.RelationTenantRead] = false
	code, _ = qaHTTPJSON(t, srv, http.MethodGet, "/api/v1/tenants/acme/deployment-plans/"+plan.ID, "good", nil)
	if code != http.StatusForbidden {
		t.Fatalf("status without tenant.read = %d, want 403", code)
	}
}

func TestQAHTTPRejectsMalformedPlanInputs(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PlanRequest)
		want   string
	}{
		{name: "empty body", mutate: func(r *PlanRequest) { *r = PlanRequest{} }, want: "deployment source is required"},
		{name: "invalid mode", mutate: func(r *PlanRequest) { r.Observability.Mode = "bogus" }, want: "observability mode"},
		{name: "non-object spec", mutate: func(r *PlanRequest) { r.Deployment.Spec = json.RawMessage(`[]`) }, want: "deployment spec"},
		{name: "native observability conflict", mutate: func(r *PlanRequest) { r.Deployment.Spec = json.RawMessage(`{"observability":{"enabled":true}}`) }, want: "managed_chart_native_observability_conflict"},
		{name: "unknown owner team", mutate: func(r *PlanRequest) { r.Deployment.OwnerTeam = "unknown" }, want: "ownerTeam"},
		{name: "chart latest", mutate: func(r *PlanRequest) {
			r.Source = &Source{Kind: SourceChart, SourceID: "hiroba", Ref: "oci://ghcr.io/7k-hiroba/payments-api/charts/payments-api", Version: "latest", Digest: testDigest}
		}, want: "chart_version_invalid"},
		{name: "chart mutable digest", mutate: func(r *PlanRequest) {
			r.Source = &Source{Kind: SourceChart, SourceID: "hiroba", Ref: "oci://ghcr.io/7k-hiroba/payments-api/charts/payments-api", Version: "1.4.0", Digest: "latest"}
		}, want: "chart_digest_invalid"},
		{name: "chart tagged repository", mutate: func(r *PlanRequest) {
			r.Source = &Source{Kind: SourceChart, SourceID: "hiroba", Ref: "oci://ghcr.io/7k-hiroba/payments-api/charts/payments-api:1.4.0", Version: "1.4.0", Digest: testDigest}
		}, want: "chart_ref_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _, _, _ := serviceFixture(t)
			srv := newQAHTTPServer(t, svc, &qaHTTPAuthorizer{defaultAllow: true}, &qaHTTPRepoWrite{})
			request := deployRequest()
			tc.mutate(&request)
			code, raw := qaHTTPJSON(t, srv, http.MethodPost, "/api/v1/tenants/acme/deployment-plans/preflight", "good", request)
			if code != http.StatusUnprocessableEntity || !strings.Contains(string(raw), tc.want) {
				t.Fatalf("preflight = %d %s, want 422 containing %q", code, raw, tc.want)
			}
		})
	}
}

func TestQAHTTPExistingInstanceProvisionAfterSkip(t *testing.T) {
	svc, _, _, _, _ := serviceFixture(t)
	repoWrite := &qaHTTPRepoWrite{}
	srv := newQAHTTPServer(t, svc, &qaHTTPAuthorizer{defaultAllow: true}, repoWrite)
	request := deployRequest()
	request.Observability.Mode = ModeSkip
	request.IdempotencyKey = "qa-skip"
	initial := qaHTTPPreflight(t, srv, request)
	plan := qaHTTPSubmit(t, srv, qaHTTPSubmitRequest(initial, request.IdempotencyKey))
	if plan.Companion != nil || plan.AppInstanceID == "" {
		t.Fatalf("skip submit = %#v", plan)
	}

	code, raw := qaHTTPJSON(t, srv, http.MethodGet, "/api/v1/tenants/acme/instances/"+plan.AppInstanceID+"/observability", "good", nil)
	if code != http.StatusOK || !strings.Contains(string(raw), `"mode":"skip"`) {
		t.Fatalf("skipped status = %d %s", code, raw)
	}
	existing := PlanRequest{Operation: OperationProvisionExisting, InstanceID: plan.AppInstanceID,
		Deployment: DeploymentInput{Spec: json.RawMessage(`{}`)}, Observability: ObservabilityInput{Mode: ModeProvision}, IdempotencyKey: "qa-existing"}
	review := qaHTTPPreflight(t, srv, existing)
	provisioned := qaHTTPSubmit(t, srv, qaHTTPSubmitRequest(review, existing.IdempotencyKey))
	if provisioned.Companion == nil || provisioned.Companion.AppInstanceID != plan.AppInstanceID || len(provisioned.Companion.Links) != 0 {
		t.Fatalf("later provision = %#v", provisioned)
	}
	if len(repoWrite.instanceIDs) != 1 || repoWrite.instanceIDs[0] != plan.AppInstanceID {
		t.Fatalf("recorded repo-write enforcement = %v", repoWrite.instanceIDs)
	}
}
