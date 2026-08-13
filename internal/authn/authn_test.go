package authn

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubValidator struct {
	id  *Identity
	err error
}

func (s stubValidator) Validate(context.Context, string) (*Identity, error) {
	return s.id, s.err
}

func TestParseOrganizations(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want int
	}{
		{"array", `["acme","globex"]`, 2},
		{"object", `{"acme":{}}`, 1},
		{"string", `"acme"`, 1},
		{"empty", `null`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orgs, err := ParseOrganizations([]byte(tc.raw))
			if err != nil {
				t.Fatalf("ParseOrganizations: %v", err)
			}
			if len(orgs) != tc.want {
				t.Errorf("got %v, want %d orgs", orgs, tc.want)
			}
		})
	}
}

func TestMiddleware(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := IdentityFromContext(r.Context())
		if id == nil || id.Subject != "u1" {
			t.Error("identity not in context")
		}
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(stubValidator{id: &Identity{Subject: "u1"}})(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMiddlewareRejectsMissingToken(t *testing.T) {
	h := Middleware(stubValidator{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next must not be called")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMiddlewareRejectsInvalidToken(t *testing.T) {
	h := Middleware(stubValidator{err: errors.New("bad")})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next must not be called")
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer bad")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireOrg(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mw := RequireOrg("org")(ok)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/teams", nil)
	req.SetPathValue("org", "acme")
	id := &Identity{Subject: "u1", Organizations: []string{"acme"}}
	req = req.WithContext(context.WithValue(req.Context(), ctxKey{}, id))
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("member: status = %d, want 200", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/other/teams", nil)
	req2.SetPathValue("org", "other")
	req2 = req2.WithContext(context.WithValue(req2.Context(), ctxKey{}, id))
	rec2 := httptest.NewRecorder()
	mw.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("non-member: status = %d, want 403", rec2.Code)
	}
}
