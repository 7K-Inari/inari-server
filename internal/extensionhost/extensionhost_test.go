package extensionhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/go-chi/chi/v5"

	pluginv1 "github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1/pluginv1connect"

	"github.com/7K-Inari/inari-server/internal/authn"
	"github.com/7K-Inari/inari-server/internal/types"
)

// fakePlugin implements PluginContractServiceHandler for handshake tests.
type fakePlugin struct {
	info *pluginv1.PluginInfo
}

func (f *fakePlugin) GetInfo(context.Context, *connect.Request[pluginv1.GetInfoRequest]) (*connect.Response[pluginv1.GetInfoResponse], error) {
	return connect.NewResponse(&pluginv1.GetInfoResponse{Info: f.info}), nil
}
func (f *fakePlugin) GetCapabilities(context.Context, *connect.Request[pluginv1.GetCapabilitiesRequest]) (*connect.Response[pluginv1.GetCapabilitiesResponse], error) {
	return connect.NewResponse(&pluginv1.GetCapabilitiesResponse{}), nil
}
func (f *fakePlugin) Invoke(context.Context, *connect.Request[pluginv1.InvokeRequest]) (*connect.Response[pluginv1.InvokeResponse], error) {
	return connect.NewResponse(&pluginv1.InvokeResponse{}), nil
}
func (f *fakePlugin) HealthCheck(context.Context, *connect.Request[pluginv1.HealthCheckRequest]) (*connect.Response[pluginv1.HealthCheckResponse], error) {
	return connect.NewResponse(&pluginv1.HealthCheckResponse{Status: pluginv1.HealthCheckResponse_SERVING_STATUS_SERVING}), nil
}

func pluginServer(t *testing.T, info *pluginv1.PluginInfo) *httptest.Server {
	t.Helper()
	_, h := pluginv1connect.NewPluginContractServiceHandler(&fakePlugin{info: info})
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv
}

func TestVerifyHandshake(t *testing.T) {
	ext := &types.Extension{Name: "argocd", Version: "0.1.0"}

	t.Run("ok", func(t *testing.T) {
		srv := pluginServer(t, &pluginv1.PluginInfo{Name: "argocd", Version: "0.1.0", ApiVersion: "1"})
		info, err := VerifyHandshake(context.Background(), srv.URL, ext)
		if err != nil {
			t.Fatalf("VerifyHandshake: %v", err)
		}
		if info.GetName() != "argocd" {
			t.Errorf("info = %v", info)
		}
	})

	t.Run("protocol version mismatch", func(t *testing.T) {
		srv := pluginServer(t, &pluginv1.PluginInfo{Name: "argocd", Version: "0.1.0", ApiVersion: "99"})
		_, err := VerifyHandshake(context.Background(), srv.URL, ext)
		if !errors.Is(err, ErrProtocolVersion) {
			t.Errorf("err = %v, want ErrProtocolVersion", err)
		}
	})

	t.Run("identity mismatch", func(t *testing.T) {
		srv := pluginServer(t, &pluginv1.PluginInfo{Name: "evil", Version: "0.1.0", ApiVersion: "1"})
		_, err := VerifyHandshake(context.Background(), srv.URL, ext)
		if !errors.Is(err, ErrPluginIdentity) {
			t.Errorf("err = %v, want ErrPluginIdentity", err)
		}
	})

	t.Run("unreachable", func(t *testing.T) {
		_, err := VerifyHandshake(context.Background(), "http://127.0.0.1:1", ext)
		if err == nil || errors.Is(err, ErrProtocolVersion) || errors.Is(err, ErrPluginIdentity) {
			t.Errorf("err = %v, want dial error", err)
		}
	})
}

func TestVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugin")
	content := []byte("fake plugin binary")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)

	t.Run("match", func(t *testing.T) {
		if err := VerifyChecksum(path, hex.EncodeToString(sum[:])); err != nil {
			t.Fatalf("VerifyChecksum: %v", err)
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		if err := VerifyChecksum(path, strings.Repeat("0", 64)); !errors.Is(err, ErrChecksumMismatch) {
			t.Errorf("err = %v, want ErrChecksumMismatch", err)
		}
	})
	t.Run("empty expected passes (dial mode)", func(t *testing.T) {
		if err := VerifyChecksum(path, ""); err != nil {
			t.Errorf("err = %v", err)
		}
	})
}

type fakeValidator struct{ id *authn.Identity }

func (f fakeValidator) Validate(_ context.Context, token string) (*authn.Identity, error) {
	if token == "bad" {
		return nil, fmt.Errorf("invalid")
	}
	return f.id, nil
}

type fakeAuthorizer struct{ allow bool }

func (f fakeAuthorizer) Check(context.Context, string, string, string) (bool, error) {
	return f.allow, nil
}
func (f fakeAuthorizer) ListObjects(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

type staticGetter struct{ ext *types.Extension }

func (s staticGetter) GetByName(context.Context, string) (*types.Extension, error) {
	if s.ext == nil {
		return nil, ErrNotFound
	}
	return s.ext, nil
}

func TestProxyServe(t *testing.T) {
	type captured struct {
		auth, cookie, user, org, path string
	}
	var got captured
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = captured{
			auth:   r.Header.Get("Authorization"),
			cookie: r.Header.Get("Cookie"),
			user:   r.Header.Get("X-Inari-User"),
			org:    r.Header.Get("X-Inari-Org"),
			path:   r.URL.Path,
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("plugin-response"))
	}))
	defer upstream.Close()

	ext := &types.Extension{
		ID: "extension:1", OrgID: "org:1", Name: "argocd", Version: "0.1.0",
		Endpoint: upstream.URL, State: types.ExtensionStateReady,
	}
	newRouter := func(reg Registry, az fakeAuthorizer) *chi.Mux {
		p := NewProxy(reg, fakeValidator{id: &authn.Identity{Subject: "user-1"}}, az)
		r := chi.NewRouter()
		p.Mount(r)
		return r
	}
	do := func(r http.Handler, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Cookie", "session=secret")
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		return rec
	}

	t.Run("proxies with authz, strips sensitive headers", func(t *testing.T) {
		rec := do(newRouter(staticGetter{ext}, fakeAuthorizer{allow: true}), "good")
		if rec.Code != http.StatusOK || rec.Body.String() != "plugin-response" {
			t.Fatalf("resp = %d %q", rec.Code, rec.Body.String())
		}
		if got.auth != "" || got.cookie != "" {
			t.Errorf("sensitive headers leaked: auth=%q cookie=%q", got.auth, got.cookie)
		}
		if got.user != "user-1" || got.org != "org:1" {
			t.Errorf("identity headers: user=%q org=%q", got.user, got.org)
		}
		if got.path != "/applications" {
			t.Errorf("path = %q", got.path)
		}
	})

	t.Run("denies without invoke grant", func(t *testing.T) {
		rec := do(newRouter(staticGetter{ext}, fakeAuthorizer{allow: false}), "good")
		if rec.Code != http.StatusForbidden {
			t.Errorf("code = %d", rec.Code)
		}
	})

	t.Run("rejects bad token", func(t *testing.T) {
		rec := do(newRouter(staticGetter{ext}, fakeAuthorizer{allow: true}), "bad")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("code = %d", rec.Code)
		}
	})

	t.Run("404 unknown extension", func(t *testing.T) {
		rec := do(newRouter(staticGetter{}, fakeAuthorizer{allow: true}), "good")
		if rec.Code != http.StatusNotFound {
			t.Errorf("code = %d", rec.Code)
		}
	})

	t.Run("spoofed identity headers are overwritten", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("X-Inari-User", "attacker")
		req.Header.Set("X-Inari-Org", "org:evil")
		rec := httptest.NewRecorder()
		newRouter(staticGetter{ext}, fakeAuthorizer{allow: true}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		if got.user != "user-1" || got.org != "org:1" {
			t.Errorf("identity headers: user=%q org=%q", got.user, got.org)
		}
	})

	t.Run("spoofed org header stripped for platform-global extension", func(t *testing.T) {
		global := *ext
		global.OrgID = ""
		req := httptest.NewRequest(http.MethodGet, "/api/extensions/argocd/applications", nil)
		req.Header.Set("Authorization", "Bearer good")
		req.Header.Set("X-Inari-Org", "org:evil")
		rec := httptest.NewRecorder()
		newRouter(staticGetter{&global}, fakeAuthorizer{allow: true}).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("code = %d", rec.Code)
		}
		if got.org != "" {
			t.Errorf("org header = %q, want stripped", got.org)
		}
	})

	t.Run("502 when not ready", func(t *testing.T) {
		pending := *ext
		pending.State = types.ExtensionStatePending
		rec := do(newRouter(staticGetter{&pending}, fakeAuthorizer{allow: true}), "good")
		if rec.Code != http.StatusBadGateway {
			t.Errorf("code = %d", rec.Code)
		}
	})

	t.Run("502 when upstream dead (crash isolation)", func(t *testing.T) {
		dead := *ext
		dead.Endpoint = "http://127.0.0.1:1"
		rec := do(newRouter(staticGetter{&dead}, fakeAuthorizer{allow: true}), "good")
		if rec.Code != http.StatusBadGateway {
			t.Errorf("code = %d", rec.Code)
		}
	})
}
