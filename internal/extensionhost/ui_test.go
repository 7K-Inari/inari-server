package extensionhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestUiAssetServerSiblingChunks(t *testing.T) {
	chunk := []byte(`/* chunk 616 */`)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/616.js") {
			_, _ = w.Write(chunk)
			return
		}
		_, _ = w.Write([]byte(`/* remoteEntry */`))
	}))
	t.Cleanup(upstream.Close)

	org := &types.Organization{ID: "org:1", Slug: "acme"}
	e := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd", Version: "0.1.0",
		Ui: &types.UiExtensionDescriptor{RemoteEntry: upstream.URL + "/ui/remoteEntry.js", Enabled: true},
	}
	f := &RemoteEntryFetcher{}
	s := NewUiAssetServer(fakeUiRegistry{e}, fakeTenants{org}, f)
	r := chi.NewRouter()
	s.Mount(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/extensions/ui/argocd/616.js", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body = %q", rec.Code, rec.Body.String())
	}
	if rec.Body.String() != string(chunk) {
		t.Errorf("body = %q", rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
		t.Errorf("content-type = %q", ct)
	}

	// Path traversal is rejected.
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/tenants/acme/extensions/ui/argocd/..%2Fsecret", nil)
	r.ServeHTTP(rec2, req2)
	if rec2.Code == http.StatusOK {
		t.Errorf("traversal must not be served")
	}
}

// TestUiAssetServerHandlerMatrix pins the /extensions/ui/* serving contract
// (issue #76, guards PR #73): remoteEntry.js 200, arbitrary sibling chunks
// 200 with per-suffix content types, and a battery of path-traversal vectors
// rejected without ever reaching the upstream source.
func TestUiAssetServerHandlerMatrix(t *testing.T) {
	files := map[string][]byte{
		"/ui/remoteEntry.js": []byte(`/* remoteEntry */`),
		"/ui/616.js":         []byte(`/* chunk 616 */`),
		"/ui/styles.css":     []byte(`body { color: red }`),
		"/ui/chunk.js.map":   []byte(`{"version":3}`),
	}
	var mu sync.Mutex
	upstreamHits := map[string]int{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamHits[r.URL.Path]++
		mu.Unlock()
		if body, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(body)
			return
		}
		http.Error(w, "not found", http.StatusNotFound)
	}))
	t.Cleanup(upstream.Close)
	hits := func(p string) int {
		mu.Lock()
		defer mu.Unlock()
		return upstreamHits[p]
	}

	org := &types.Organization{ID: "org:1", Slug: "acme"}
	e := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd", Version: "0.1.0",
		Ui: &types.UiExtensionDescriptor{RemoteEntry: upstream.URL + "/ui/remoteEntry.js", Enabled: true},
	}
	s := NewUiAssetServer(fakeUiRegistry{e}, fakeTenants{org}, &RemoteEntryFetcher{})
	r := chi.NewRouter()
	s.Mount(r)

	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		r.ServeHTTP(rec, req)
		return rec
	}
	const base = "/api/v1/tenants/acme/extensions/ui/argocd/"

	t.Run("remoteEntry.js 200", func(t *testing.T) {
		rec := get(base + "remoteEntry.js")
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d body = %q", rec.Code, rec.Body.String())
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/javascript; charset=utf-8" {
			t.Errorf("content-type = %q", ct)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
			t.Errorf("cache-control = %q", cc)
		}
		if rec.Body.String() != string(files["/ui/remoteEntry.js"]) {
			t.Errorf("body = %q", rec.Body.String())
		}
	})

	siblings := []struct {
		name  string
		file  string
		ctype string
	}{
		{"webpack chunk", "616.js", "application/javascript; charset=utf-8"},
		{"stylesheet", "styles.css", "text/css; charset=utf-8"},
		{"source map", "chunk.js.map", "application/json; charset=utf-8"},
	}
	for _, tc := range siblings {
		t.Run("sibling "+tc.name+" 200", func(t *testing.T) {
			rec := get(base + tc.file)
			if rec.Code != http.StatusOK {
				t.Fatalf("code = %d body = %q", rec.Code, rec.Body.String())
			}
			if ct := rec.Header().Get("Content-Type"); ct != tc.ctype {
				t.Errorf("content-type = %q, want %q", ct, tc.ctype)
			}
			if rec.Body.String() != string(files["/ui/"+tc.file]) {
				t.Errorf("body = %q", rec.Body.String())
			}
			if n := hits("/ui/" + tc.file); n != 1 {
				t.Errorf("upstream hits for /ui/%s = %d, want 1 (sibling must resolve next to remoteEntry.js)", tc.file, n)
			}
		})
	}

	longName := strings.Repeat("a", 200) + ".js"
	traversals := []struct {
		name string
		path string
	}{
		{"encoded slash", base + "..%2Fsecret"},
		{"encoded dots", base + "%2e%2e%2fsecret"},
		{"double-dot slash combo", base + "....//secret"},
		{"nested subdirectory", base + "sub/dir.js"},
		{"leading dash", base + "-bad.js"},
		{"oversized name", base + longName},
	}
	for _, tc := range traversals {
		t.Run("traversal rejected: "+tc.name, func(t *testing.T) {
			before := 0
			mu.Lock()
			for _, n := range upstreamHits {
				before += n
			}
			mu.Unlock()
			rec := get(tc.path)
			if rec.Code == http.StatusOK {
				t.Fatalf("traversal %q must not be served", tc.path)
			}
			after := 0
			mu.Lock()
			for _, n := range upstreamHits {
				after += n
			}
			mu.Unlock()
			if after != before {
				t.Errorf("traversal %q reached the upstream source (%d -> %d hits)", tc.path, before, after)
			}
		})
	}
}

type fakeDirFetcher struct {
	files map[string][]byte
	err   error
}

func (f fakeDirFetcher) FetchDir(context.Context, string) (map[string][]byte, error) {
	return f.files, f.err
}

func TestFetchAssetOCI(t *testing.T) {
	desc := &types.UiExtensionDescriptor{
		RemoteEntryOci: "registry.example/ui/ext:v1", Enabled: true,
	}
	files := map[string][]byte{
		"remoteEntry.js": []byte("/* entry */"),
		"616.js":         []byte("/* chunk */"),
	}

	t.Run("serves sibling chunk from the OCI dir artifact", func(t *testing.T) {
		f := &RemoteEntryFetcher{OCI: fakeDirFetcher{files: files}}
		body, err := f.FetchAsset(context.Background(), desc, "616.js")
		if err != nil {
			t.Fatal(err)
		}
		if string(body) != "/* chunk */" {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("missing asset in artifact errors", func(t *testing.T) {
		f := &RemoteEntryFetcher{OCI: fakeDirFetcher{files: files}}
		if _, err := f.FetchAsset(context.Background(), desc, "nope.js"); err == nil {
			t.Fatal("want error")
		}
	})

	t.Run("OCI source is cached per file", func(t *testing.T) {
		f := &RemoteEntryFetcher{OCI: fakeDirFetcher{files: files}, CacheTTL: time.Minute}
		if _, err := f.FetchAsset(context.Background(), desc, "616.js"); err != nil {
			t.Fatal(err)
		}
		// Second call must come from cache: swap the fake's files.
		f.OCI = fakeDirFetcher{err: errors.New("registry down")}
		if _, err := f.FetchAsset(context.Background(), desc, "616.js"); err != nil {
			t.Fatalf("cache miss: %v", err)
		}
	})

	t.Run("invalid asset names rejected", func(t *testing.T) {
		f := &RemoteEntryFetcher{OCI: fakeDirFetcher{files: files}}
		if _, err := f.FetchAsset(context.Background(), desc, "../escape.js"); err == nil {
			t.Fatal("want error")
		}
	})
}
