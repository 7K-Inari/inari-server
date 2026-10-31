// Render cutover (operator sunset Phase 1, parent plan §4.2/§6): instead of
// platform.inari.io/v1alpha1 CRs for the operator, the tenant's platform
// resources are rendered as internal/renderer source descriptors and
// committed to the hub-facing platform repo (decision D3) — native
// DNSEndpoint/AppProject manifests, a tenantnamespace KRO instance, and
// provider-keycloak TenantRealm/TenantClient namespaced XRs. Gated by the
// platform_resources.gitops_render feature flag (off = legacy CR render,
// the dual-run lever).
//
// Render-time logic ported from the operator's controllers:
//   - DNS zone containment (dns_controller.go): every record must live
//     inside the tenant zone — validated here, before anything is committed.
//   - Dex repo auto-union (argoproject_controller.go): tenant AppProjects
//     always allow the official dexidp chart repo so Dex Applications sync.
//
// impersonateServiceAccount is dropped entirely (D3): the write path is
// server → git → hub ArgoCD, authorized at the repo level.
package platformresources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/7K-Inari/inari-server/internal/featureflags"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/renderer"
	"github.com/7K-Inari/inari-server/internal/tenancy"
	"github.com/7K-Inari/inari-server/internal/types"
)

const (
	// sharedDNSZone is the platform-owned DNS zone every tenant record
	// lives in (shared-zone model; the old DNSRecord CR's zoneRef "shared"
	// resolved to this zone).
	sharedDNSZone = "7kgroup.org"
	// dexChartRepoURL is the official dexidp Helm chart repository,
	// unioned into every tenant AppProject (ported from the operator's
	// argoproject_controller.go auto-union).
	dexChartRepoURL = "https://charts.dexidp.io"
	// tenantNamespaceRGDRef is the well-known ref for the platform's
	// tenantnamespace KRO ResourceGraphDefinition.
	tenantNamespaceRGDRef = "platform/tenantnamespace"
	// argoCDNamespace is where Application/AppProject objects live.
	argoCDNamespace = "argocd"
	// localClusterServer is the hub-local ArgoCD destination.
	localClusterServer = "https://kubernetes.default.svc"
)

// tenantNamespaceRGD mirrors the schema coordinates of the tenantnamespace
// ResourceGraphDefinition (release-bundle charts/inari-platform-graphs,
// authored by W1-2). The renderer's kro handler only consumes
// spec.schema.apiVersion/kind to stamp the generated CRD's coordinates onto
// the instance manifest; the RGD itself is versioned and applied via the
// release-bundle gitops (platform-rgd Application).
var tenantNamespaceRGD = []byte(`apiVersion: kro.run/v1alpha1
kind: ResourceGraphDefinition
metadata:
  name: tenantnamespace
spec:
  schema:
    group: stacks.inari.io
    apiVersion: v1alpha1
    kind: TenantNamespace
    scope: Namespaced
`)

// resolvePlatformRGD resolves the well-known platform RGD refs. The
// tenantnamespace RGD is platform infrastructure (not a catalog item), so
// resolution is static rather than catalog-backed.
func resolvePlatformRGD(_ context.Context, ref string) ([]byte, error) {
	if ref == tenantNamespaceRGDRef {
		return tenantNamespaceRGD, nil
	}
	return nil, fmt.Errorf("platformresources: unknown platform RGD ref %q", ref)
}

// FlagEvaluator is the feature-flag read seam (featureflags.Resolver).
type FlagEvaluator interface {
	Bool(ctx context.Context, key, clusterID string) bool
}

// TenantLookupByID resolves an org by its stable ID (tenancy.Service seam)
// — registration knows the cluster's OrgID and claim rendering needs the
// slug for repo paths and TenantReference fields.
type TenantLookupByID interface {
	GetTenantByID(ctx context.Context, id string) (*types.Organization, error)
}

// WithFlags wires the feature-flag resolver gating the render cutover.
func (s *Service) WithFlags(f FlagEvaluator) *Service { s.flags = f; return s }

// WithTenantLookup wires the by-ID tenant lookup used by the keycloak
// client claim render.
func (s *Service) WithTenantLookup(l TenantLookupByID) *Service { s.tenantLookup = l; return s }

// gitopsRenderEnabled reports whether the descriptor render path is active.
// Nil-safe: no flags wired (tests, legacy wiring) means legacy CR render.
func (s *Service) gitopsRenderEnabled(ctx context.Context) bool {
	return s.flags != nil && s.flags.Bool(ctx, featureflags.KeyPlatformResourcesGitOpsRender, "")
}

// tenantNamespaceName is the tenant's hub namespace (unchanged contract).
func tenantNamespaceName(slug string) string { return "tenant-" + slug }

// dnsNamesInZone reports whether name equals zone or is a subdomain of it
// (ported from the operator's dns_controller.go).
func dnsNamesInZone(name, zone string) bool {
	name = strings.TrimSuffix(name, ".")
	zone = strings.TrimSuffix(zone, ".")
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// dnsEndpoint is one ExternalDNS endpoint record.
type dnsEndpoint struct {
	DNSName    string
	RecordType string
	Targets    []string
	TTL        int64
}

// validateZoneContainment enforces the tenant-zone boundary at render time:
// every record must live inside the zone (the check the operator's
// DNSRecord reconciler ran against the referenced DNSZone).
func validateZoneContainment(eps []dnsEndpoint, zone string) error {
	for _, ep := range eps {
		if !dnsNamesInZone(ep.DNSName, zone) {
			return fmt.Errorf("platformresources: dnsName %q outside zone %q", ep.DNSName, zone)
		}
	}
	return nil
}

// tenantDNSEndpoints are the tenant's records under the shared platform
// zone (shared-record mode, unchanged from the legacy bootstrap).
func tenantDNSEndpoints(org *types.Organization) []dnsEndpoint {
	return []dnsEndpoint{{
		DNSName:    tenantNamespaceName(org.Slug) + "." + sharedDNSZone,
		RecordType: "CNAME",
		Targets:    []string{"inari." + sharedDNSZone},
	}}
}

// dnsEndpointDoc renders the native ExternalDNS DNSEndpoint the operator's
// DNSRecord controller used to materialize.
func dnsEndpointDoc(org *types.Organization) (map[string]any, error) {
	eps := tenantDNSEndpoints(org)
	if err := validateZoneContainment(eps, sharedDNSZone); err != nil {
		return nil, err
	}
	out := make([]any, 0, len(eps))
	for _, ep := range eps {
		targets := make([]any, 0, len(ep.Targets))
		for _, t := range ep.Targets {
			targets = append(targets, t)
		}
		out = append(out, map[string]any{
			"dnsName":    ep.DNSName,
			"recordType": ep.RecordType,
			"targets":    targets,
			"recordTTL":  ep.TTL,
		})
	}
	return map[string]any{
		"apiVersion": "externaldns.k8s.io/v1alpha1",
		"kind":       "DNSEndpoint",
		"metadata": map[string]any{
			"name":      org.Slug,
			"namespace": tenantNamespaceName(org.Slug),
			"labels":    map[string]any{"platform.inari.io/org": org.Slug},
		},
		"spec": map[string]any{"endpoints": out},
	}, nil
}

// unionSourceRepos appends the dexidp chart repo when missing (ported from
// the operator's argoproject_controller.go: tenant projects must allow it
// so Dex Applications sync; converged on every render).
func unionSourceRepos(repos []string) []string {
	out := make([]string, 0, len(repos)+1)
	out = append(out, repos...)
	found := false
	for _, r := range repos {
		if r == dexChartRepoURL {
			found = true
			break
		}
	}
	if !found {
		out = append(out, dexChartRepoURL)
	}
	return out
}

// appProjectDoc renders the per-tenant ArgoCD AppProject constraining the
// tenant's hub-side Applications (decision D3 belt-and-suspenders:
// destination restriction to the tenant namespace, source restriction to
// the platform repo + the dex chart repo).
func appProjectDoc(org *types.Organization, repoURL string) map[string]any {
	repos := make([]any, 0, 2)
	for _, r := range unionSourceRepos([]string{repoURL}) {
		repos = append(repos, r)
	}
	return map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "AppProject",
		"metadata": map[string]any{
			"name":      tenantNamespaceName(org.Slug),
			"namespace": argoCDNamespace,
			"labels":    map[string]any{"platform.inari.io/org": org.Slug},
		},
		"spec": map[string]any{
			"description": fmt.Sprintf("Tenant %s project (managed by inari-server)", org.Slug),
			"sourceRepos": repos,
			"destinations": []any{map[string]any{
				"server":    localClusterServer,
				"namespace": tenantNamespaceName(org.Slug),
			}},
			"clusterResourceWhitelist":   []any{map[string]any{"group": "*", "kind": "*"}},
			"namespaceResourceWhitelist": []any{map[string]any{"group": "*", "kind": "*"}},
		},
	}
}

// realmClaimDoc renders the provider-keycloak TenantRealm namespaced XR (identity.inari.io/v1alpha1, W1-2 XRD; Crossplane v2: the namespaced XR is the user-facing kind).
func realmClaimDoc(org *types.Organization) map[string]any {
	return map[string]any{
		"apiVersion": "identity.inari.io/v1alpha1",
		"kind":       "TenantRealm",
		"metadata": map[string]any{
			"name":      org.Slug,
			"namespace": tenantNamespaceName(org.Slug),
			"labels":    map[string]any{"platform.inari.io/org": org.Slug},
		},
		"spec": map[string]any{
			"tenantID":    org.Slug,
			"namespace":   tenantNamespaceName(org.Slug),
			"displayName": org.DisplayName,
			"enabled":     true,
		},
	}
}

// tenantIssuerURL derives the tenant realm's issuer URL from the platform
// issuer (…/realms/<platform-realm> → …/realms/<tenant realm>). The
// platform issuer is always a Keycloak realm URL; a path-less issuer gets
// the /realms/<realm> suffix rather than a mangled host.
func tenantIssuerURL(issuerURL, realm string) string {
	u, err := url.Parse(issuerURL)
	if err != nil || u.Host == "" {
		// Not a URL — treat it as an opaque realm-URL prefix.
		base := strings.TrimSuffix(issuerURL, "/")
		if i := strings.LastIndex(base, "/"); i >= 0 {
			return base[:i+1] + realm
		}
		return base + "/realms/" + realm
	}
	path := strings.TrimSuffix(u.Path, "/")
	if i := strings.LastIndex(path, "/"); i > 0 {
		path = path[:i]
	} else {
		path = "/realms"
	}
	u.Path = path + "/" + realm
	return u.String()
}

// clientClaimDocs renders the per-client document set (W1-2 contract,
// examples/keycloak-client-secret-delivery.yaml): the TenantClient XR
// plus the ExternalSecret materializing the operator-compatible
// credentials Secret, and the once-per-tenant ESO plumbing (ServiceAccount,
// Role, RoleBinding, namespaced SecretStore) — re-rendered on every commit,
// idempotently (same content, same paths).
func clientClaimDocs(org *types.Organization, claimName, clientID, issuerURL string) []map[string]any {
	ns := tenantNamespaceName(org.Slug)
	tenantLabel := map[string]any{"platform.inari.io/tenant": org.Slug}
	sa := map[string]any{
		"apiVersion": "v1",
		"kind":       "ServiceAccount",
		"metadata":   map[string]any{"name": "eso-tenant-secret-reader", "namespace": ns, "labels": tenantLabel},
	}
	role := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata":   map[string]any{"name": "eso-tenant-secret-reader", "namespace": ns, "labels": tenantLabel},
		"rules": []any{map[string]any{
			"apiGroups": []any{""}, "resources": []any{"secrets"}, "verbs": []any{"get", "list", "watch"},
		}},
	}
	roleBinding := map[string]any{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "RoleBinding",
		"metadata":   map[string]any{"name": "eso-tenant-secret-reader", "namespace": ns, "labels": tenantLabel},
		"roleRef":    map[string]any{"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "eso-tenant-secret-reader"},
		"subjects": []any{map[string]any{
			"kind": "ServiceAccount", "name": "eso-tenant-secret-reader", "namespace": ns,
		}},
	}
	secretStore := map[string]any{
		"apiVersion": "external-secrets.io/v1",
		"kind":       "SecretStore",
		"metadata":   map[string]any{"name": "keycloak-client-connections", "namespace": ns, "labels": tenantLabel},
		"spec": map[string]any{
			"provider": map[string]any{
				"kubernetes": map[string]any{
					"server": map[string]any{
						"url": localClusterServer,
						// ESO v1: caProvider nests under server (strict
						// decoding rejects kubernetes.caProvider).
						"caProvider": map[string]any{
							"type": "ConfigMap", "name": "kube-root-ca.crt", "key": "ca.crt", "namespace": ns,
						},
					},
					"auth": map[string]any{"serviceAccount": map[string]any{"name": "eso-tenant-secret-reader"}},
				},
			},
		},
	}
	claim := map[string]any{
		"apiVersion": "identity.inari.io/v1alpha1",
		"kind":       "TenantClient",
		"metadata": map[string]any{
			"name":      claimName,
			"namespace": ns,
			"labels":    map[string]any{"platform.inari.io/org": org.Slug},
		},
		"spec": map[string]any{
			"tenantID":               org.Slug,
			"namespace":              ns,
			"realm":                  org.Slug,
			"clientID":               clientID,
			"public":                 false,
			"serviceAccountsEnabled": true,
		},
	}
	externalSecret := map[string]any{
		"apiVersion": "external-secrets.io/v1",
		"kind":       "ExternalSecret",
		"metadata":   map[string]any{"name": claimName + "-keycloak-client", "namespace": ns, "labels": tenantLabel},
		"spec": map[string]any{
			"refreshInterval": "1h",
			"secretStoreRef":  map[string]any{"kind": "SecretStore", "name": "keycloak-client-connections"},
			"target": map[string]any{
				"name": claimName + "-keycloak-client",
				"template": map[string]any{
					"type":     "Opaque",
					"metadata": map[string]any{"labels": tenantLabel},
					"data": map[string]any{
						"client-id":     clientID,
						"issuer":        issuerURL,
						"client-secret": "{{ .client_secret }}",
					},
				},
			},
			"data": []any{map[string]any{
				"secretKey": "client_secret",
				"remoteRef": map[string]any{
					"key":      claimName + "-keycloak-connection",
					"property": "attribute.client_secret",
				},
			}},
		},
	}
	return []map[string]any{sa, role, roleBinding, secretStore, claim, externalSecret}
}

// renderDescriptor marshals docs into a source descriptor payload and runs
// the renderer. docs become the inline manifest set (JSON array of YAML
// strings) for manifests/crossplane kinds; the kro kind takes the instance
// spec directly.
func (s *Service) renderDescriptor(ctx context.Context, desc types.SourceDescriptor, p renderer.RenderParams) ([]gitprovider.File, error) {
	files, err := s.renders.Render(ctx, desc, p)
	if err != nil {
		return nil, err
	}
	out := make([]gitprovider.File, len(files))
	for i, f := range files {
		out[i] = gitprovider.File{Path: f.Path, Content: f.Content}
	}
	return out, nil
}

// manifestsDescriptor packs YAML docs into a manifests source descriptor.
func manifestsDescriptor(docs ...map[string]any) (types.SourceDescriptor, error) {
	raw, err := yamlDocsJSON(docs)
	if err != nil {
		return types.SourceDescriptor{}, err
	}
	return types.SourceDescriptor{
		Kind:      types.SourceKindManifests,
		Manifests: &types.ManifestSource{Inline: raw},
	}, nil
}

// crossplaneDescriptor packs YAML docs into a crossplane source descriptor.
func crossplaneDescriptor(docs ...map[string]any) (types.SourceDescriptor, error) {
	raw, err := yamlDocsJSON(docs)
	if err != nil {
		return types.SourceDescriptor{}, err
	}
	return types.SourceDescriptor{
		Kind:       types.SourceKindCrossplane,
		Crossplane: &types.XPSource{Manifests: raw},
	}, nil
}

// yamlDocsJSON marshals each doc to YAML and packs the set as a JSON array
// (the inline-documents convention shared by the manifests/crossplane
// handlers).
func yamlDocsJSON(docs []map[string]any) (json.RawMessage, error) {
	strs := make([]string, len(docs))
	for i, d := range docs {
		raw, err := yaml.Marshal(d)
		if err != nil {
			return nil, fmt.Errorf("platformresources: marshal doc %d: %w", i, err)
		}
		strs[i] = string(raw)
	}
	raw, err := json.Marshal(strs)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// RenderTenantFiles renders the tenant's platform resources for the
// hub-facing platform repo. Flag off: the legacy platform.inari.io CR
// manifests (RenderTenantManifests). Flag on: renderer source descriptors —
// per-tenant AppProject, native DNSEndpoint, the tenantnamespace KRO
// instance, and the TenantRealm XR — each as an ArgoCD Application +
// manifests under tenants/<slug>/. repoURL is the repo's clone URL (the
// Application source); it is unused by the legacy path.
func (s *Service) RenderTenantFiles(ctx context.Context, org *types.Organization, repoURL string) ([]gitprovider.File, error) {
	if !s.gitopsRenderEnabled(ctx) {
		return RenderTenantManifests(org), nil
	}
	return s.renderTenantDescriptors(ctx, org, repoURL)
}

// renderTenantDescriptors renders the full descriptor set for one tenant.
func (s *Service) renderTenantDescriptors(ctx context.Context, org *types.Organization, repoURL string) ([]gitprovider.File, error) {
	base := renderer.RenderParams{
		Namespace:  tenantNamespaceName(org.Slug),
		RepoURL:    repoURL,
		BaseBranch: "main",
		Project:    tenantNamespaceName(org.Slug),
		DeployMode: types.AddonDeployModeApplication,
	}
	var out []gitprovider.File
	appendFiles := func(files []gitprovider.File, err error) error {
		if err != nil {
			return err
		}
		out = append(out, files...)
		return nil
	}

	// Per-tenant AppProject (destination/source restrictions, D3). Lives in
	// the argocd namespace under the default project — it is the guardrail
	// the tenant-scoped Applications below run under, not tenant content.
	projectDoc := appProjectDoc(org, repoURL)
	projectDesc, err := manifestsDescriptor(projectDoc)
	if err != nil {
		return nil, err
	}
	p := base
	p.ID, p.Name, p.Namespace, p.Project, p.Path = "tenant-"+org.Slug+"-project", "tenant-"+org.Slug, argoCDNamespace, "default",
		"tenants/"+org.Slug+"/project"
	if err := appendFiles(s.renderDescriptor(ctx, projectDesc, p)); err != nil {
		return nil, fmt.Errorf("platformresources: render appproject: %w", err)
	}

	// Native DNSEndpoint (render-time zone containment).
	dnsDoc, err := dnsEndpointDoc(org)
	if err != nil {
		return nil, err
	}
	dnsDesc, err := manifestsDescriptor(dnsDoc)
	if err != nil {
		return nil, err
	}
	p = base
	p.ID, p.Name, p.Path = "tenant-"+org.Slug+"-dns", org.Slug, "tenants/"+org.Slug+"/dns"
	if err := appendFiles(s.renderDescriptor(ctx, dnsDesc, p)); err != nil {
		return nil, fmt.Errorf("platformresources: render dnsendpoint: %w", err)
	}

	// tenantnamespace KRO instance. The RGD is namespaced and creates the
	// tenant namespace itself, so the instance lives in the pre-existing
	// "default" hub namespace under the default project (platform
	// bootstrap plumbing, not tenant content).
	nsDesc := types.SourceDescriptor{
		Kind: types.SourceKindKRO,
		KRO: &types.KROSource{
			RGDRef: tenantNamespaceRGDRef,
			Instance: json.RawMessage(fmt.Sprintf(`{"tenantID":%q,"namespace":%q}`,
				org.Slug, tenantNamespaceName(org.Slug))),
		},
	}
	p = base
	p.ID, p.Name, p.Namespace, p.Project, p.Path = "tenant-"+org.Slug+"-namespace", "tenant-"+org.Slug, "default", "default",
		"tenants/"+org.Slug+"/namespace"
	if err := appendFiles(s.renderDescriptor(ctx, nsDesc, p)); err != nil {
		return nil, fmt.Errorf("platformresources: render tenantnamespace instance: %w", err)
	}

	// TenantRealm XR (provider-keycloak, hub-side; D1/D3).
	realmDesc, err := crossplaneDescriptor(realmClaimDoc(org))
	if err != nil {
		return nil, err
	}
	p = base
	p.ID, p.Name, p.Path = "tenant-"+org.Slug+"-realm", org.Slug, "tenants/"+org.Slug+"/keycloak/realm"
	if err := appendFiles(s.renderDescriptor(ctx, realmDesc, p)); err != nil {
		return nil, fmt.Errorf("platformresources: render tenantrealm claim: %w", err)
	}
	return out, nil
}

// TenantRenderPaths returns the repo-relative paths of the tenant's
// rendered files in the hub-facing platform repo — the teardown delete
// set. The union always covers the legacy CR paths; with the flag on it
// adds the tenant descriptor paths (D7: dev/staging tenants may have been
// rendered by either generation). Per-cluster TenantClient XRs are
// committed at registration, not by the tenant render, so their paths are
// enumerated from the keycloak-client rows — regardless of the flag,
// which may have flipped between registration and teardown (deleting
// paths that were never committed is a no-op).
func (s *Service) TenantRenderPaths(ctx context.Context, slug string) ([]string, error) {
	paths := TenantManifestPaths(slug)
	if s.gitopsRenderEnabled(ctx) {
		// Paths are slug-derived only; a synthetic org reproduces them exactly.
		files, err := s.renderTenantDescriptors(ctx, &types.Organization{Slug: slug}, "https://invalid/platform.git")
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			paths = append(paths, f.Path)
		}
	}
	clientPaths, err := s.clientClaimRenderPaths(ctx, slug)
	if err != nil {
		return nil, err
	}
	return append(paths, clientPaths...), nil
}

// clientClaimRenderPaths enumerates the committed per-cluster claim paths
// from the tenant's keycloak-client rows. Best-effort when the tenant
// resolver or store is unwired (legacy construction): the claim render
// requires the same wiring, so nothing could have been committed. A
// deleted org likewise leaves nothing to enumerate.
func (s *Service) clientClaimRenderPaths(ctx context.Context, slug string) ([]string, error) {
	if s.tenants == nil || s.store == nil || s.db == nil {
		return nil, nil
	}
	org, err := s.tenants.GetTenant(ctx, slug)
	if errors.Is(err, tenancy.ErrOrgNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("platformresources: resolve org for teardown paths: %w", err)
	}
	rows, err := s.store.List(ctx, s.db.Pool, org.ID)
	if err != nil {
		return nil, fmt.Errorf("platformresources: list client rows for teardown: %w", err)
	}
	var paths []string
	synthetic := &types.Organization{Slug: slug}
	for _, r := range rows {
		if r.Kind != types.PlatformKindKeycloakClient {
			continue
		}
		files, err := s.renderClientClaim(ctx, synthetic, r.Name, "", "https://invalid/platform.git")
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			paths = append(paths, f.Path)
		}
	}
	return paths, nil
}

// renderClientClaim renders the per-client XR file set (the
// TenantClient XR + ESO plumbing) — shared by RenderKeycloakClientClaim
// (commit) and TenantRenderPaths (teardown delete set) so the two layouts
// can never drift.
func (s *Service) renderClientClaim(ctx context.Context, org *types.Organization, clientID, issuerURL, repoURL string) ([]gitprovider.File, error) {
	// Claim name must be RFC 1123: client IDs embed uppercase ULIDs, so the
	// claim lowercases and spec.clientID carries the real identifier (the
	// AGENTS.md ULID rule for ArgoCD object names).
	claimName := strings.ToLower(clientID)
	docs := clientClaimDocs(org, claimName, clientID, tenantIssuerURL(issuerURL, org.Slug))
	desc, err := crossplaneDescriptor(docs...)
	if err != nil {
		return nil, err
	}
	return s.renderDescriptor(ctx, desc, renderer.RenderParams{
		ID:         "tenant-" + org.Slug + "-client-" + claimName,
		Name:       claimName,
		Namespace:  tenantNamespaceName(org.Slug),
		Path:       "tenants/" + org.Slug + "/keycloak/client-" + claimName,
		Project:    tenantNamespaceName(org.Slug),
		RepoURL:    repoURL,
		BaseBranch: "main",
		DeployMode: types.AddonDeployModeApplication,
	})
}

// RenderKeycloakClientClaim renders the provider-keycloak TenantClient
// XR (+ ESO secret-delivery plumbing) for a per-cluster OIDC client into
// the hub-facing platform repo under tenants/<slug>/keycloak/client-<id>/
// and commits it (decision D3: never to team repos). Dual-run: the caller
// keeps upserting the keycloak-client desired-state row alongside, so the
// resources view and status tracking are unchanged across the Phase 3
// provider cutover (the XR is now the live manager; D1).
//
// Returns rendered=false (no error) when the cutover flag is off or the
// platform GitOps repo is unwired — the caller falls back to the legacy
// desired-state row. Errors abort the caller BEFORE the registration token
// is burned, so the agent can retry (retry-safe); repeat calls re-commit
// identical content (idempotent).
func (s *Service) RenderKeycloakClientClaim(ctx context.Context, orgID, clusterID, clientID, issuerURL string) (bool, error) {
	if !s.gitopsRenderEnabled(ctx) || s.git == nil || s.platformGitOpsRepo == "" || s.tenantLookup == nil {
		return false, nil
	}
	org, err := s.tenantLookup.GetTenantByID(ctx, orgID)
	if err != nil {
		return false, fmt.Errorf("platformresources: resolve org for client claim: %w", err)
	}
	repoURL, err := s.git.EnsureRepo(ctx, s.platformGitOpsRepo)
	if err != nil {
		return false, fmt.Errorf("platformresources: ensure platform gitops repo: %w", err)
	}
	files, err := s.renderClientClaim(ctx, org, clientID, issuerURL, repoURL)
	if err != nil {
		return false, fmt.Errorf("platformresources: render tenantclient claim: %w", err)
	}
	if _, err := s.git.CommitFiles(ctx, s.platformGitOpsRepo, "main", files,
		"feat: keycloak client claim "+clientID+" for cluster "+clusterID); err != nil {
		return false, fmt.Errorf("platformresources: commit tenantclient claim: %w", err)
	}
	return true, nil
}
