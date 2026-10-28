// Package renderer is the source-agnostic render pipeline (Feature C
// foundation, parent plan §6): it ingests a types.SourceDescriptor and
// always emits ArgoCD Application/ApplicationSet manifests plus supporting
// files — never system-specific apply logic. Adding a composition type is
// registering a handler, not touching the deploy/update machinery.
//
// The renderer is a pure library: no HTTP, no DB, no gitprovider. Callers
// resolve the target repo (gitprovider.RepoResolver) and the cluster
// selector (decision 8: server-side targeting) and commit the returned
// files themselves.
package renderer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrNotSupported is returned (wrapped) by handlers for source kinds that
// are registered but not yet implemented (crossplane, kustomize).
var ErrNotSupported = errors.New("renderer: source kind not yet supported")

// App-name prefixes (parent plan §6): instances render inari-<id>, addons
// inari-addon-<id>, fleet-wide addons inari-addonset-<id>.
const (
	PrefixInstance = "inari"
	PrefixAddon    = "inari-addon"
	PrefixAddonSet = "inari-addonset"
)

// RenderedFile is one file to commit at a repo-relative path (mirrors
// gitprovider.File so callers can hand the result straight to the git
// write path).
type RenderedFile struct {
	Path    string
	Content []byte
}

// ClusterTarget is one already-resolved cluster. The caller evaluates the
// cluster selector server-side (decision 8); the renderer never queries
// inventory and never touches ArgoCD cluster-secret labels.
type ClusterTarget struct {
	ID     string // inventory cluster id
	Name   string // used in list-generator elements and overlay paths
	Server string // ArgoCD destination server; empty = local cluster
}

// localServer is the default ArgoCD destination (tenant-local ArgoCD).
const localServer = "https://kubernetes.default.svc"

// RenderParams carries everything a handler needs to render one workload.
type RenderParams struct {
	Name        string                // workload name (KRO metadata.name, helm release, overlay path segment)
	Namespace   string                // destination namespace; empty = "default"
	ID          string                // instance/addon id — app-name base
	AppPrefix   string                // PrefixInstance | PrefixAddon; empty = ID verbatim
	DeployMode  types.AddonDeployMode // application | applicationset
	Clusters    []ClusterTarget       // application mode: exactly 1; applicationset: 1..n
	Prune       bool                  // default false (decision 2); orchestrator instance deploys pass true
	SyncOptions []string              // e.g. take-ownership for adoption; emitted verbatim
	Values      json.RawMessage       // helm values (JSON object, marshaled to YAML)
	RepoURL     string                // resolved clone URL of the target repo (git source / $values ref)
	BaseBranch  string                // targetRevision for git sources
	Path        string                // repo-relative base path (clusters/<c>/<item>/<inst> or addons/<name>)
	Project     string                // ArgoCD project; empty = "default"
}

// Renderer renders one source descriptor into commit-ready files.
type Renderer interface {
	Render(ctx context.Context, desc types.SourceDescriptor, params RenderParams) ([]RenderedFile, error)
}

// Handler renders one source kind.
type Handler interface {
	Render(ctx context.Context, desc types.SourceDescriptor, params RenderParams) ([]RenderedFile, error)
}

// ResolveRGDFunc resolves a KROSource.RGDRef to the RGD document (YAML).
// Wired by callers to the catalog; the ref format is caller-side
// convention and opaque to the renderer.
type ResolveRGDFunc func(ctx context.Context, ref string) ([]byte, error)

// Registry dispatches source descriptors to per-kind handlers.
type Registry struct {
	handlers map[types.SourceKind]Handler
}

// New returns a Registry with all known kinds registered: helm, kro (with
// resolveRGD, which may be nil for callers that never render kro), and
// manifests fully implemented; crossplane and kustomize as stubs so
// enabling them later is purely additive.
func New(resolveRGD ResolveRGDFunc) *Registry {
	r := &Registry{handlers: map[types.SourceKind]Handler{}}
	r.Register(types.SourceKindHelm, helmHandler{})
	r.Register(types.SourceKindKRO, &kroHandler{resolve: resolveRGD})
	r.Register(types.SourceKindManifests, manifestsHandler{})
	r.Register(types.SourceKindCrossplane, stubHandler{kind: types.SourceKindCrossplane})
	r.Register(types.SourceKindKustomize, stubHandler{kind: types.SourceKindKustomize})
	return r
}

// Register adds or replaces the handler for a kind — the additive
// extension seam.
func (r *Registry) Register(kind types.SourceKind, h Handler) {
	r.handlers[kind] = h
}

// Render validates the descriptor and dispatches to the kind's handler.
func (r *Registry) Render(ctx context.Context, desc types.SourceDescriptor, params RenderParams) ([]RenderedFile, error) {
	if err := validateDescriptor(desc); err != nil {
		return nil, err
	}
	h, ok := r.handlers[desc.Kind]
	if !ok {
		return nil, fmt.Errorf("renderer: no handler registered for source kind %q", desc.Kind)
	}
	if err := params.validate(); err != nil {
		return nil, err
	}
	return h.Render(ctx, desc, params)
}

// validateDescriptor checks that the kind-matching payload is set.
func validateDescriptor(desc types.SourceDescriptor) error {
	var ok bool
	switch desc.Kind {
	case types.SourceKindHelm:
		ok = desc.Helm != nil
	case types.SourceKindKRO:
		ok = desc.KRO != nil
	case types.SourceKindCrossplane:
		ok = desc.Crossplane != nil
	case types.SourceKindManifests:
		ok = desc.Manifests != nil
	case types.SourceKindKustomize:
		ok = desc.Kustomize != nil
	default:
		// Unknown kinds fall through to the registry's handler lookup.
		return nil
	}
	if !ok {
		return fmt.Errorf("renderer: source kind %q requires its %s payload", desc.Kind, desc.Kind)
	}
	return nil
}

// validate checks deploy-mode invariants shared by all handlers.
func (p RenderParams) validate() error {
	if p.ID == "" {
		return errors.New("renderer: params.ID is required")
	}
	if p.Path == "" {
		return errors.New("renderer: params.Path is required")
	}
	switch p.DeployMode {
	case "", types.AddonDeployModeApplication:
		if len(p.Clusters) > 1 {
			return fmt.Errorf("renderer: application deploy mode takes exactly one cluster, got %d", len(p.Clusters))
		}
	case types.AddonDeployModeApplicationSet:
		if len(p.Clusters) == 0 {
			return errors.New("renderer: applicationset deploy mode requires at least one cluster")
		}
		for _, c := range p.Clusters {
			if c.Name == "" {
				return errors.New("renderer: applicationset cluster targets require Name")
			}
		}
	default:
		return fmt.Errorf("renderer: unknown deploy mode %q", p.DeployMode)
	}
	return nil
}

// namespace returns the destination namespace (default "default").
func (p RenderParams) namespace() string {
	if p.Namespace == "" {
		return "default"
	}
	return p.Namespace
}

// project returns the ArgoCD project (default "default").
func (p RenderParams) project() string {
	if p.Project == "" {
		return "default"
	}
	return p.Project
}

// appName computes the Application/ApplicationSet name. In applicationset
// mode the ApplicationSet itself is inari-addonset-<id>; empty prefix
// yields ID verbatim (orchestrator back-compat wrappers).
func (p RenderParams) appName() string {
	if p.DeployMode == types.AddonDeployModeApplicationSet {
		return PrefixAddonSet + "-" + p.ID
	}
	if p.AppPrefix == "" {
		return p.ID
	}
	return p.AppPrefix + "-" + p.ID
}
