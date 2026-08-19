//go:build integration

package cloudaccounts_test

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

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/cloudaccounts"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeValidator struct{ err error }

func (f fakeValidator) AssumeRoleDryRun(context.Context, string, string, string) error {
	return f.err
}

func itDB(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	return database
}

func itService(d *db.DB, v cloudaccounts.STSValidator) *cloudaccounts.Service {
	return cloudaccounts.NewService(d, cloudaccounts.NewStore(), audit.NewStore(), v)
}

var itInput = cloudaccounts.RegisterInput{
	Provider:   "aws",
	AccountID:  "123456789012",
	RoleARN:    "arn:aws:iam::123456789012:role/inari-crossplane",
	ExternalID: "ext-abc",
	RunContext: types.CloudAccountRunContextTenant,
}

func TestRegisterValidateActive(t *testing.T) {
	svc := itService(itDB(t), fakeValidator{})
	ctx := context.Background()

	acct, err := svc.Register(ctx, "user-1", "org:1", itInput)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if acct.State != types.CloudAccountStatePendingValidation {
		t.Fatalf("state = %q, want pending_validation", acct.State)
	}

	acct, err = svc.Validate(ctx, "user-1", "org:1", acct.ID)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if acct.State != types.CloudAccountStateActive || acct.ValidatedAt == nil {
		t.Errorf("state=%q validatedAt=%v", acct.State, acct.ValidatedAt)
	}

	got, err := svc.Get(ctx, "org:1", acct.ID)
	if err != nil || got.State != types.CloudAccountStateActive {
		t.Errorf("get: state=%v err=%v", got, err)
	}
	list, err := svc.List(ctx, "org:1")
	if err != nil || len(list) != 1 {
		t.Errorf("list: n=%d err=%v", len(list), err)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	svc := itService(itDB(t), fakeValidator{})
	ctx := context.Background()
	if _, err := svc.Register(ctx, "user-1", "org:1", itInput); err != nil {
		t.Fatal(err)
	}
	_, err := svc.Register(ctx, "user-1", "org:1", itInput)
	if !errors.Is(err, cloudaccounts.ErrAlreadyRegistered) {
		t.Fatalf("err = %v, want ErrAlreadyRegistered", err)
	}
}

func TestValidateFailureMarksInvalid(t *testing.T) {
	svc := itService(itDB(t), fakeValidator{err: errors.New("access denied")})
	ctx := context.Background()
	acct, err := svc.Register(ctx, "user-1", "org:1", itInput)
	if err != nil {
		t.Fatal(err)
	}
	acct, err = svc.Validate(ctx, "user-1", "org:1", acct.ID)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if acct.State != types.CloudAccountStateInvalid || acct.ValidationErr == "" {
		t.Errorf("state=%q err=%q", acct.State, acct.ValidationErr)
	}
}

func TestValidateUnavailableStaysPending(t *testing.T) {
	svc := itService(itDB(t), cloudaccounts.DisabledValidator{})
	ctx := context.Background()
	acct, err := svc.Register(ctx, "user-1", "org:1", itInput)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Validate(ctx, "user-1", "org:1", acct.ID)
	if !errors.Is(err, cloudaccounts.ErrValidationUnavailable) {
		t.Fatalf("err = %v, want ErrValidationUnavailable", err)
	}
	got, err := svc.Get(ctx, "org:1", acct.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != types.CloudAccountStatePendingValidation {
		t.Errorf("state = %q, want pending_validation", got.State)
	}
}

func TestDeregister(t *testing.T) {
	svc := itService(itDB(t), fakeValidator{})
	ctx := context.Background()
	acct, err := svc.Register(ctx, "user-1", "org:1", itInput)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Deregister(ctx, "user-1", "org:1", acct.ID); err != nil {
		t.Fatalf("deregister: %v", err)
	}
	_, err = svc.Get(ctx, "org:1", acct.ID)
	if !errors.Is(err, cloudaccounts.ErrNotFound) {
		t.Fatalf("get after deregister: err = %v, want ErrNotFound", err)
	}
	// Re-registering after deregister works (unique row is gone).
	if _, err := svc.Register(ctx, "user-1", "org:1", itInput); err != nil {
		t.Fatalf("re-register: %v", err)
	}
}

type itValidator struct{}

func (itValidator) Validate(_ context.Context, raw string) (*authn.Identity, error) {
	if raw == "good" {
		return &authn.Identity{Subject: "user-1", Organizations: []string{"acme"}}, nil
	}
	return nil, errors.New("invalid token")
}

type itAuthorizer struct{ allow bool }

func (a itAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return a.allow, nil
}
func (a itAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type itTenants map[string]*types.Organization

func (t itTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if o, ok := t[slug]; ok {
		return o, nil
	}
	return nil, tenancy.ErrOrgNotFound
}

type itClusters struct{}

func (itClusters) GetCluster(_ context.Context, id string) (*types.Cluster, error) {
	if id == "cluster:1" {
		return &types.Cluster{
			ID: "cluster:1", OrgID: "org:1", Name: "kind-dev", State: types.ClusterStateActive,
			Labels: map[string]string{"inari.dev/oidc-issuer": "https://issuer.kind.example"},
		}, nil
	}
	return nil, errors.New("unknown cluster")
}

func itReq(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, string) {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rdr)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// TestCloudAccountsHTTP covers the REST surface: register → validate → get →
// providerconfig → deregister, plus error mapping (422/409/404).
func TestCloudAccountsHTTP(t *testing.T) {
	database := itDB(t)
	svc := itService(database, fakeValidator{})
	router, api := httpserver.NewRouter(slog.Default(), itValidator{}, database)
	cloudaccounts.NewHandler(svc, itTenants{"acme": {ID: "org:1", Slug: "acme"}}, itClusters{}, itAuthorizer{allow: true}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	defer srv.Close()

	// Bad input → 422.
	code, body := itReq(t, srv, "POST", "/api/v1/tenants/acme/cloud-accounts", "good", `{"accountId":"123","roleArn":"nope"}`)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("bad input: %d %s", code, body)
	}

	// Register → 200.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/cloud-accounts", "good",
		`{"accountId":"123456789012","roleArn":"arn:aws:iam::123456789012:role/inari-crossplane","externalId":"ext-abc"}`)
	if code != http.StatusOK {
		t.Fatalf("register: %d %s", code, body)
	}
	var regOut struct {
		Account types.CloudAccount `json:"account"`
	}
	if err := json.Unmarshal([]byte(body), &regOut); err != nil {
		t.Fatal(err)
	}
	acctID := regOut.Account.ID
	if regOut.Account.State != types.CloudAccountStatePendingValidation {
		t.Errorf("state = %q", regOut.Account.State)
	}

	// Duplicate → 409.
	code, _ = itReq(t, srv, "POST", "/api/v1/tenants/acme/cloud-accounts", "good",
		`{"accountId":"123456789012","roleArn":"arn:aws:iam::123456789012:role/inari-crossplane"}`)
	if code != http.StatusConflict {
		t.Errorf("duplicate: %d, want 409", code)
	}

	// Validate → active.
	code, body = itReq(t, srv, "POST", "/api/v1/tenants/acme/cloud-accounts/"+acctID+"/validate", "good", "")
	if code != http.StatusOK || !strings.Contains(body, `"active"`) {
		t.Errorf("validate: %d %s", code, body)
	}

	// List + get.
	if code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/cloud-accounts", "good", ""); code != http.StatusOK || !strings.Contains(body, acctID) {
		t.Errorf("list: %d %s", code, body)
	}
	if code, _ = itReq(t, srv, "GET", "/api/v1/tenants/acme/cloud-accounts/"+acctID, "good", ""); code != http.StatusOK {
		t.Errorf("get: %d", code)
	}

	// ProviderConfig renders as YAML.
	code, body = itReq(t, srv, "GET", "/api/v1/tenants/acme/cloud-accounts/"+acctID+"/providerconfig?clusterId=cluster:1", "good", "")
	if code != http.StatusOK || !strings.Contains(body, "kind: ProviderConfig") || !strings.Contains(body, "source: WebIdentity") {
		t.Errorf("providerconfig: %d\n%s", code, body)
	}
	// Unknown cluster → 404.
	if code, _ = itReq(t, srv, "GET", "/api/v1/tenants/acme/cloud-accounts/"+acctID+"/providerconfig?clusterId=cluster:zzz", "good", ""); code != http.StatusNotFound {
		t.Errorf("providerconfig unknown cluster: %d, want 404", code)
	}

	// Deregister → 204; get → 404.
	code, _ = itReq(t, srv, "DELETE", "/api/v1/tenants/acme/cloud-accounts/"+acctID, "good", "")
	if code != http.StatusNoContent {
		t.Errorf("deregister: %d, want 204", code)
	}
	if code, _ = itReq(t, srv, "GET", "/api/v1/tenants/acme/cloud-accounts/"+acctID, "good", ""); code != http.StatusNotFound {
		t.Errorf("get after deregister: %d, want 404", code)
	}

	// Unauthenticated → 401.
	if code, _ = itReq(t, srv, "GET", "/api/v1/tenants/acme/cloud-accounts", "", ""); code != http.StatusUnauthorized {
		t.Errorf("unauthenticated: %d, want 401", code)
	}
}
