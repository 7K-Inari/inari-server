package tenancy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/httpserver"
	"github.com/7K-Inari/inari-server/internal/types"
)

// stubBrokerManager fails loudly if validation ever lets a call through.
type stubBrokerManager struct{}

func (stubBrokerManager) CreateIdP(context.Context, BrokerIdPSpec) error {
	return errors.New("stub: CreateIdP called")
}
func (stubBrokerManager) UpdateIdP(context.Context, BrokerIdPSpec) error {
	return errors.New("stub: UpdateIdP called")
}
func (stubBrokerManager) DeleteIdP(context.Context, string) error {
	return errors.New("stub: DeleteIdP called")
}
func (stubBrokerManager) LinkIdPToOrg(context.Context, string, string) error {
	return errors.New("stub: LinkIdPToOrg called")
}
func (stubBrokerManager) UnlinkIdPFromOrg(context.Context, string, string) error {
	return errors.New("stub: UnlinkIdPFromOrg called")
}
func (stubBrokerManager) SetOrgDomains(context.Context, string, []string) error {
	return errors.New("stub: SetOrgDomains called")
}

func TestBrokeredIdPAlias(t *testing.T) {
	if got := brokeredIdPAlias("acme", "sso"); got != "org-acme-sso" {
		t.Errorf("brokeredIdPAlias = %q, want org-acme-sso", got)
	}
}

func TestValidateDomainHints(t *testing.T) {
	valid := [][]string{
		nil,
		{"acme.com"},
		{"*.subs.acme.com", "a.b.c.d.e.f.g.h.i.com"}, // 10 parts max
	}
	for _, hints := range valid {
		if err := validateDomainHints(hints); err != nil {
			t.Errorf("valid hints %v rejected: %v", hints, err)
		}
	}
	invalid := [][]string{
		{"localhost"},                       // 1 part
		{"Acme.com"},                        // uppercase
		{"*.com"},                           // wildcard over a single label
		{"-bad.acme.com"},                   // leading hyphen
		{"a.b.c.d.e.f.g.h.i.j.com"},         // 11 parts
		{"acme.com", "not a domain"},        // one bad entry fails all
	}
	for _, hints := range invalid {
		if err := validateDomainHints(hints); err == nil {
			t.Errorf("invalid hints %v accepted", hints)
		}
	}
}

func TestOrgDomainsKeepsPlaceholder(t *testing.T) {
	domains := orgDomains("acme", []string{"acme.com"})
	if len(domains) != 2 || domains[0] != "acme.inari.local" || domains[1] != "acme.com" {
		t.Errorf("domains = %v", domains)
	}
}

// TestCreateBrokeredIdPValidatesBeforeKeycloak guards the input validation
// that runs before any Keycloak or DB access, so a nil-backed service is
// enough.
func validBrokerInput() *types.BrokeredIdP {
	return &types.BrokeredIdP{Alias: "sso", IssuerURL: "https://idp.example.com", ClientID: "inari-acme"}
}

func TestCreateBrokeredIdPValidatesBeforeKeycloak(t *testing.T) {
	svc := NewService(nil, nil, nil, nil).WithIdentityProviderManager(stubBrokerManager{})
	in := validBrokerInput()
	in.IssuerURL = "http://idp.example.com"
	if _, err := svc.CreateBrokeredIdP(context.Background(), "u1", "acme", in, ""); err == nil {
		t.Error("http issuer URL accepted")
	}
	in = validBrokerInput()
	in.DomainHints = []string{"BAD DOMAIN"}
	if _, err := svc.CreateBrokeredIdP(context.Background(), "u1", "acme", in, ""); err == nil {
		t.Error("invalid domain hint accepted")
	}
}

// TestBrokerRoutesRequireOrgMembership verifies the coarse PEP: without the
// org claim every broker route is 403 before any service call (the handler
// is constructed with a nil service, so reaching it would panic).
func TestBrokerRoutesRequireOrgMembership(t *testing.T) {
	router, api := httpserver.NewRouter(slog.New(slog.NewTextHandler(io.Discard, nil)),
		stubValidator{id: &authn.Identity{Subject: "u1"}}, stubReady{})
	NewHandler(nil, flagAuthorizer{allow: true}).RegisterRoutes(api)
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	for _, tc := range []struct {
		method, path, body string
	}{
		{http.MethodGet, "/api/v1/tenants/acme/identity/providers", ""},
		{http.MethodPost, "/api/v1/tenants/acme/identity/providers", `{"alias":"sso","issuerUrl":"https://idp.example.com","clientId":"c","clientSecret":"s"}`},
		{http.MethodGet, "/api/v1/tenants/acme/identity/providers/sso", ""},
		{http.MethodPatch, "/api/v1/tenants/acme/identity/providers/sso", "{}"},
		{http.MethodDelete, "/api/v1/tenants/acme/identity/providers/sso", ""},
	} {
		resp := testTokenReq(t, tc.method, srv.URL+tc.path, tc.body)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s %s: got %d, want 403", tc.method, tc.path, resp.StatusCode)
		}
	}
}
