package extensionhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

func TestValidateUiInput(t *testing.T) {
	base := RegisterUiInput{OrgID: "org:1", Name: "argocd", Version: "0.1.0", RemoteEntry: "https://example.com/remoteEntry.js"}

	t.Run("ok", func(t *testing.T) {
		if err := validateUiInput(base); err != nil {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("name and version required", func(t *testing.T) {
		in := base
		in.Name = ""
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v", err)
		}
		in = base
		in.Version = ""
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("orgID required", func(t *testing.T) {
		in := base
		in.OrgID = ""
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("exactly one source", func(t *testing.T) {
		in := base
		in.RemoteEntry = ""
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("neither source: err = %v", err)
		}
		in = base
		in.RemoteEntryOci = "ghcr.io/x/y:1"
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("both sources: err = %v", err)
		}
		in = base
		in.RemoteEntry = ""
		in.RemoteEntryOci = "ghcr.io/x/y:1"
		if err := validateUiInput(in); err != nil {
			t.Errorf("oci only: err = %v", err)
		}
	})
	t.Run("slot kind enum", func(t *testing.T) {
		in := base
		in.Slots = []types.UiSlotDescriptor{{Kind: "bogus", Name: "x"}}
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("err = %v", err)
		}
		in.Slots = []types.UiSlotDescriptor{{Kind: types.UiSlotClusterTab, Name: ""}}
		if err := validateUiInput(in); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("empty slot name: err = %v", err)
		}
		in.Slots = []types.UiSlotDescriptor{{Kind: types.UiSlotClusterTab, Name: "argocd-health"}}
		if err := validateUiInput(in); err != nil {
			t.Errorf("valid slot: err = %v", err)
		}
	})
}

func TestRemoteEntryFetcherHTTP(t *testing.T) {
	content := []byte(`console.log("remoteEntry");`)
	sum := sha256.Sum256(content)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(upstream.Close)

	t.Run("fetches and caches", func(t *testing.T) {
		f := &RemoteEntryFetcher{}
		d := &types.UiExtensionDescriptor{RemoteEntry: upstream.URL}
		body, err := f.Fetch(context.Background(), d)
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != string(content) {
			t.Errorf("body = %q", body)
		}
	})
	t.Run("checksum match", func(t *testing.T) {
		f := &RemoteEntryFetcher{}
		d := &types.UiExtensionDescriptor{RemoteEntry: upstream.URL, Checksum: hex.EncodeToString(sum[:])}
		if _, err := f.Fetch(context.Background(), d); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("checksum mismatch", func(t *testing.T) {
		f := &RemoteEntryFetcher{}
		d := &types.UiExtensionDescriptor{RemoteEntry: upstream.URL, Checksum: "deadbeef"}
		if _, err := f.Fetch(context.Background(), d); !errors.Is(err, ErrRemoteEntryFetch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("rejects non-https non-loopback", func(t *testing.T) {
		f := &RemoteEntryFetcher{}
		d := &types.UiExtensionDescriptor{RemoteEntry: "http://169.254.169.254/latest"}
		if _, err := f.Fetch(context.Background(), d); !errors.Is(err, ErrRemoteEntryFetch) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("upstream error", func(t *testing.T) {
		f := &RemoteEntryFetcher{}
		d := &types.UiExtensionDescriptor{RemoteEntry: "http://127.0.0.1:1/remoteEntry.js"}
		if _, err := f.Fetch(context.Background(), d); !errors.Is(err, ErrRemoteEntryFetch) {
			t.Errorf("err = %v", err)
		}
	})
}

type fakeUiRegistry struct{ ext *types.Extension }

func (f fakeUiRegistry) GetUi(_ context.Context, orgID, name string) (*types.Extension, error) {
	if f.ext == nil || f.ext.OrgID != orgID || f.ext.Name != name || f.ext.Ui == nil {
		return nil, ErrNotFound
	}
	return f.ext, nil
}

type fakeTenants struct{ org *types.Organization }

func (f fakeTenants) GetTenant(_ context.Context, slug string) (*types.Organization, error) {
	if f.org == nil || f.org.Slug != slug {
		return nil, tenancy.ErrOrgNotFound
	}
	return f.org, nil
}

func TestUiAssetServer(t *testing.T) {
	content := []byte(`/* remoteEntry */`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(content)
	}))
	t.Cleanup(upstream.Close)

	org := &types.Organization{ID: "org:1", Slug: "acme"}
	uiExt := func() *types.Extension {
		return &types.Extension{
			ID: "extension:1", OrgID: "org:1", Name: "argocd", Version: "0.1.0",
			Ui: &types.UiExtensionDescriptor{RemoteEntry: upstream.URL, Enabled: true},
		}
	}

	newRouter := func(reg UiRegistry) *chi.Mux {
		f := &RemoteEntryFetcher{}
		s := NewUiAssetServer(reg, fakeTenants{org}, f)
		r := chi.NewRouter()
		s.Mount(r)
		return r
	}
	do := func(r http.Handler) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/extensions/ui/argocd/remoteEntry.js", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	t.Run("serves javascript without auth (Module Federation script load)", func(t *testing.T) {
		rec := do(newRouter(fakeUiRegistry{uiExt()}))
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d body = %q", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
			t.Errorf("content-type = %q", ct)
		}
		if rec.Body.String() != string(content) {
			t.Errorf("body = %q", rec.Body.String())
		}
	})
	t.Run("404 unknown extension", func(t *testing.T) {
		rec := do(newRouter(fakeUiRegistry{}))
		if rec.Code != http.StatusNotFound {
			t.Errorf("code = %d", rec.Code)
		}
	})
	t.Run("404 unknown org", func(t *testing.T) {
		f := &RemoteEntryFetcher{}
		s := NewUiAssetServer(fakeUiRegistry{uiExt()}, fakeTenants{}, f)
		r := chi.NewRouter()
		s.Mount(r)
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/ghost/extensions/ui/argocd/remoteEntry.js", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("code = %d", rec.Code)
		}
	})
	t.Run("404 when disabled", func(t *testing.T) {
		e := uiExt()
		e.Ui.Enabled = false
		rec := do(newRouter(fakeUiRegistry{e}))
		if rec.Code != http.StatusNotFound {
			t.Errorf("code = %d", rec.Code)
		}
	})
}
