package renderer

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// argocd.go holds the ArgoCD Application/ApplicationSet builders shared by
// every source handler. Emission uses map[string]any + yaml.v3 (sorted
// keys → stable output for golden tests), matching the pre-existing
// orchestrator render.go style.

// gitSource is the single-source form pointing an Application at a path in
// the target repo (kro/manifests kinds).
func gitSource(p RenderParams, path string) map[string]any {
	return map[string]any{
		"repoURL":        p.RepoURL,
		"path":           path,
		"targetRevision": p.BaseBranch,
	}
}

// valuesRefSource is the multi-source $values ref: the target repo itself,
// referenced by helm valueFiles as $values/<repo-root-relative path>.
func valuesRefSource(p RenderParams) map[string]any {
	return map[string]any{
		"repoURL":        p.RepoURL,
		"targetRevision": p.BaseBranch,
		"ref":            "values",
	}
}

// baseValueFile is the workload's own values file inside the $values repo.
func baseValueFile(p RenderParams) string {
	return "$values/" + p.Path + "/values.yaml"
}

// overlayValueFile is the per-cluster values overlay (applicationset mode):
// clusters/<cluster>/<name>/values.yaml, interpolated by the list generator.
func overlayValueFile(p RenderParams) string {
	return "$values/clusters/{{cluster}}/" + p.Name + "/values.yaml"
}

// syncPolicy renders automated/selfHeal with prune per params (default off,
// decision 2) plus verbatim sync options (e.g. take-ownership on adoption).
func syncPolicy(p RenderParams) map[string]any {
	sp := map[string]any{
		"automated": map[string]any{
			"selfHeal": true,
			"prune":    p.Prune,
		},
	}
	if len(p.SyncOptions) > 0 {
		opts := make([]any, len(p.SyncOptions))
		for i, o := range p.SyncOptions {
			opts[i] = o
		}
		sp["syncOptions"] = opts
	}
	return sp
}

// destination returns the ArgoCD destination for application mode; an
// empty/absent cluster server defaults to the tenant-local ArgoCD.
func (p RenderParams) destination() map[string]any {
	server := localServer
	if len(p.Clusters) == 1 && p.Clusters[0].Server != "" {
		server = p.Clusters[0].Server
	}
	return map[string]any{"server": server, "namespace": p.namespace()}
}

// applicationSpec assembles spec from a source block: pass
// map{"source": ...} for single-source or map{"sources": [...]} for
// multi-source.
func (p RenderParams) applicationSpec(sourceBlock map[string]any) map[string]any {
	spec := map[string]any{
		"project":     p.project(),
		"destination": p.destination(),
		"syncPolicy":  syncPolicy(p),
	}
	for k, v := range sourceBlock {
		spec[k] = v
	}
	return spec
}

// buildApplication renders a single-cluster Application.
func buildApplication(p RenderParams, sourceBlock map[string]any) []byte {
	doc := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "Application",
		"metadata": map[string]any{
			"name":      p.appName(),
			"namespace": "argocd",
		},
		"spec": p.applicationSpec(sourceBlock),
	}
	out, _ := yaml.Marshal(doc)
	return out
}

// buildApplicationSet renders an ApplicationSet with a server-rendered LIST
// generator over the selected clusters (decision 8: membership computed by
// Inari, never ArgoCD cluster-secret labels). tmpl carries the template's
// source block; destination/server and the app name are generator-templated
// here so handlers stay engine-agnostic. Per-cluster Fields are merged into
// each element (reserved keys cluster/server win); AppNameTemplate overrides
// the child-name pattern; CascadeDelete adds the resources finalizer.
func buildApplicationSet(p RenderParams, tmplSourceBlock map[string]any) []byte {
	elements := make([]any, len(p.Clusters))
	for i, c := range p.Clusters {
		server := c.Server
		if server == "" {
			server = localServer
		}
		el := map[string]any{}
		for k, v := range c.Fields {
			if k == "cluster" || k == "server" {
				continue
			}
			el[k] = v
		}
		el["cluster"] = c.Name
		el["server"] = server
		elements[i] = el
	}
	tplName := p.AppPrefix + "-" + strings.ToLower(p.ID) + "-{{cluster}}"
	if p.AppNameTemplate != "" {
		tplName = p.AppNameTemplate
	}
	tplMeta := map[string]any{
		// Lowercased ID (RFC 1123), same contract as appName.
		"name": tplName,
	}
	if p.CascadeDelete {
		tplMeta["finalizers"] = []any{"resources-finalizer.argocd.argoproj.io"}
	}
	tplSpec := map[string]any{
		"project":    p.project(),
		"syncPolicy": syncPolicy(p),
		"destination": map[string]any{
			"server":    "{{server}}",
			"namespace": p.namespace(),
		},
	}
	for k, v := range tmplSourceBlock {
		tplSpec[k] = v
	}
	doc := map[string]any{
		"apiVersion": "argoproj.io/v1alpha1",
		"kind":       "ApplicationSet",
		"metadata": map[string]any{
			"name":      p.appName(),
			"namespace": "argocd",
		},
		"spec": map[string]any{
			"goTemplate": false,
			"generators": []any{
				map[string]any{"list": map[string]any{"elements": elements}},
			},
			"template": map[string]any{
				"metadata": tplMeta,
				"spec":     tplSpec,
			},
		},
	}
	out, _ := yaml.Marshal(doc)
	return out
}

// RenderSingleClusterApplication renders an Application whose source is a
// git path in the target repo. Exported for the orchestrator's back-compat
// wrappers during the render.go migration; new callers should go through
// Registry.Render.
func RenderSingleClusterApplication(p RenderParams) []byte {
	return buildApplication(p, map[string]any{"source": gitSource(p, p.Path)})
}
