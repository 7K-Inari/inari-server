// remoteEntry.js serving (plan §5.8/§5.10): the control plane serves the
// Module Federation remote entry itself — from the registered external HTTPS
// URL or from an oras OCI artifact (cosign keyless verification when a
// SignatureVerifier is configured) — so supply-chain policy is enforced
// hub-side and the console never fetches third-party origins. Responses are
// cached briefly; registrations re-POSTing a descriptor invalidate by key.
package extensionhost

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/7K-Inari/inari-server/internal/oci"
	"github.com/7K-Inari/inari-server/internal/types"
)

// DirFetcher pulls an oras directory-push artifact into name→content
// (oci.Fetcher seam; an interface so tests can fake registries).
type DirFetcher interface {
	FetchDir(ctx context.Context, ref string) (map[string][]byte, error)
}

// ErrRemoteEntryFetch is returned when the remoteEntry source cannot be
// fetched or fails integrity verification.
var ErrRemoteEntryFetch = errors.New("extensionhost: remoteEntry fetch failed")

// maxRemoteEntryBytes caps the served asset (remoteEntry.js bundles are far
// under this; the cap exists to bound hub memory on a bad upstream).
const maxRemoteEntryBytes = 5 << 20

// SignatureVerifier verifies an OCI artifact's cosign signature before its
// layers are served (mirrors scaffold.SignatureVerifier).
type SignatureVerifier interface {
	Verify(ctx context.Context, ref string) error
}

// RemoteEntryFetcher resolves and caches remoteEntry.js content.
type RemoteEntryFetcher struct {
	// HTTPClient fetches external URLs (default: 15s timeout, redirects
	// restricted to https).
	HTTPClient *http.Client
	// OCI pulls oras directory-push artifacts (default: &oci.Fetcher{}).
	OCI DirFetcher
	// Verifier, when set, runs cosign verification on OCI sources before
	// the layer is extracted (INARI_UI_EXTENSION_VERIFY=true).
	Verifier SignatureVerifier
	// CacheTTL bounds reuse of a fetched asset (default: 5m).
	CacheTTL time.Duration

	mu    sync.Mutex
	cache map[string]remoteEntryCacheEntry
}

type remoteEntryCacheEntry struct {
	body      []byte
	fetchedAt time.Time
}

func (f *RemoteEntryFetcher) ttl() time.Duration {
	if f.CacheTTL > 0 {
		return f.CacheTTL
	}
	return 5 * time.Minute
}

// Invalidate drops any cached asset for the descriptor source (called after
// a registration update).
func (f *RemoteEntryFetcher) Invalidate(desc *types.UiExtensionDescriptor) {
	if desc == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.cache, cacheKey(desc))
}

func cacheKey(desc *types.UiExtensionDescriptor) string {
	return desc.RemoteEntry + "|" + desc.RemoteEntryOci + "|" + desc.Checksum
}

// Fetch returns the remoteEntry.js bytes for the descriptor, verifying the
// optional sha256 checksum pin on either source.
func (f *RemoteEntryFetcher) Fetch(ctx context.Context, desc *types.UiExtensionDescriptor) ([]byte, error) {
	if desc == nil {
		return nil, fmt.Errorf("%w: extension has no ui descriptor", ErrRemoteEntryFetch)
	}
	key := cacheKey(desc)
	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]remoteEntryCacheEntry{}
	}
	if ent, ok := f.cache[key]; ok && time.Since(ent.fetchedAt) < f.ttl() {
		body := ent.body
		f.mu.Unlock()
		return body, nil
	}
	f.mu.Unlock()

	var body []byte
	var err error
	switch {
	case desc.RemoteEntryOci != "":
		body, err = f.fetchOCI(ctx, desc.RemoteEntryOci)
	default:
		body, err = f.fetchHTTP(ctx, desc.RemoteEntry)
	}
	if err != nil {
		return nil, err
	}
	if desc.Checksum != "" {
		sum := sha256.Sum256(body)
		if got := hex.EncodeToString(sum[:]); got != desc.Checksum {
			return nil, fmt.Errorf("%w: checksum mismatch: got %s want %s", ErrRemoteEntryFetch, got, desc.Checksum)
		}
	}
	f.mu.Lock()
	f.cache[key] = remoteEntryCacheEntry{body: body, fetchedAt: time.Now()}
	f.mu.Unlock()
	return body, nil
}

// maxAssetFileBytes caps sibling assets (webpack chunks are typically
// smaller than the entry, but we allow headroom).
const maxAssetFileBytes = 8 << 20

// assetFileRe constrains served sibling filenames to a single safe path
// segment (no traversal, no subdirectories).
var assetFileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// FetchAsset fetches a sibling asset of the remote entry (e.g. webpack async
// chunks) from the same source directory as remoteEntry.js. Only HTTP(S)
// sources are supported for sibling assets; OCI remotes must ship a
// self-contained remoteEntry.js. No checksum is applied to siblings (the
// integrity pin covers the entry; siblings come from the same origin).
func (f *RemoteEntryFetcher) FetchAsset(ctx context.Context, desc *types.UiExtensionDescriptor, file string) ([]byte, error) {
	if desc == nil {
		return nil, fmt.Errorf("%w: extension has no ui descriptor", ErrRemoteEntryFetch)
	}
	if !assetFileRe.MatchString(file) || strings.Contains(file, "..") {
		return nil, fmt.Errorf("%w: invalid asset name %q", ErrRemoteEntryFetch, file)
	}
	key := cacheKey(desc) + "|" + file
	f.mu.Lock()
	if f.cache == nil {
		f.cache = map[string]remoteEntryCacheEntry{}
	}
	if ent, ok := f.cache[key]; ok && time.Since(ent.fetchedAt) < f.ttl() {
		body := ent.body
		f.mu.Unlock()
		return body, nil
	}
	f.mu.Unlock()

	// OCI remotes: serve the sibling from the same directory-push artifact
	// (layers keyed by title) instead of requiring a self-contained entry.
	if desc.RemoteEntryOci != "" {
		if f.Verifier != nil {
			if err := f.Verifier.Verify(ctx, desc.RemoteEntryOci); err != nil {
				return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
			}
		}
		oc := f.OCI
		if oc == nil {
			oc = &oci.Fetcher{}
		}
		files, err := oc.FetchDir(ctx, desc.RemoteEntryOci)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
		}
		body, ok := files[file]
		if !ok {
			return nil, fmt.Errorf("%w: asset %s not in artifact %s", ErrRemoteEntryFetch, file, desc.RemoteEntryOci)
		}
		if len(body) > maxAssetFileBytes {
			return nil, fmt.Errorf("%w: asset %s exceeds %d bytes", ErrRemoteEntryFetch, file, maxAssetFileBytes)
		}
		f.mu.Lock()
		f.cache[key] = remoteEntryCacheEntry{body: body, fetchedAt: time.Now()}
		f.mu.Unlock()
		return body, nil
	}
	if desc.RemoteEntry == "" {
		return nil, fmt.Errorf("%w: sibling assets require a remoteEntry URL source", ErrRemoteEntryFetch)
	}

	u, err := url.Parse(desc.RemoteEntry)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: invalid remoteEntry URL %q", ErrRemoteEntryFetch, desc.RemoteEntry)
	}
	u.Path = path.Join(path.Dir(u.Path), file)
	body, err := f.fetchHTTP(ctx, u.String())
	if err != nil {
		return nil, err
	}
	if len(body) > maxAssetFileBytes {
		return nil, fmt.Errorf("%w: asset %s exceeds %d bytes", ErrRemoteEntryFetch, file, maxAssetFileBytes)
	}
	f.mu.Lock()
	f.cache[key] = remoteEntryCacheEntry{body: body, fetchedAt: time.Now()}
	f.mu.Unlock()
	return body, nil
}

func (f *RemoteEntryFetcher) fetchOCI(ctx context.Context, ref string) ([]byte, error) {
	if f.Verifier != nil {
		if err := f.Verifier.Verify(ctx, ref); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
		}
	}
	oc := f.OCI
	if oc == nil {
		oc = &oci.Fetcher{}
	}
	files, err := oc.FetchDir(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
	}
	body, ok := files["remoteEntry.js"]
	if !ok {
		return nil, fmt.Errorf("%w: artifact %s has no remoteEntry.js layer", ErrRemoteEntryFetch, ref)
	}
	if len(body) > maxRemoteEntryBytes {
		return nil, fmt.Errorf("%w: remoteEntry.js exceeds %d bytes", ErrRemoteEntryFetch, maxRemoteEntryBytes)
	}
	return body, nil
}

func (f *RemoteEntryFetcher) fetchHTTP(ctx context.Context, rawURL string) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("%w: invalid remoteEntry URL %q", ErrRemoteEntryFetch, rawURL)
	}
	// SSRF guard: https only; plain http is permitted solely for loopback
	// (dev harnesses and tests), never for routable addresses.
	if u.Scheme != "https" && (u.Scheme != "http" || !isLoopbackHost(u.Hostname())) {
		return nil, fmt.Errorf("%w: remoteEntry URL must be https (http allowed for loopback only)", ErrRemoteEntryFetch)
	}
	hc := f.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if req.URL.Scheme != "https" && !isLoopbackHost(req.URL.Hostname()) {
					return fmt.Errorf("redirect to non-https URL rejected")
				}
				return nil
			},
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
	}
	res, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: upstream returned %s", ErrRemoteEntryFetch, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, maxRemoteEntryBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRemoteEntryFetch, err)
	}
	if len(body) > maxRemoteEntryBytes {
		return nil, fmt.Errorf("%w: remoteEntry.js exceeds %d bytes", ErrRemoteEntryFetch, maxRemoteEntryBytes)
	}
	return body, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
