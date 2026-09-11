// The rendering step (M8.W3): fetches the run's template package from the
// file:// source and renders its skeleton/ tree with Go templates. The
// rendered file list is stored inline in scaffold_run_steps.result (plan
// Decision 1) so the whole render is atomic with the step-transition TX
// and the W4 creating-repo step reads it transactionally.
package scaffold

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
	"unicode/utf8"

	"github.com/7K-Inari/inari-server/internal/types"
)

// maxRenderedBytes caps the total rendered skeleton size stored inline in
// the step result (plan Decision 1); larger renders fail the step.
const maxRenderedBytes = 2 << 20 // 2 MiB

// RenderData is the template context: .Values (wizard answers), .Tenant
// (tenancy projection), .Run (ID + display name).
type RenderData struct {
	Values map[string]any
	Tenant TenantContext
	Run    RunRef
}

// RunRef is the .Run template context.
type RunRef struct {
	ID   string
	Name string
}

// RenderedFile is one rendered skeleton file (path relative to skeleton/).
type RenderedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// renderResult is the shape persisted in scaffold_run_steps.result.
type renderResult struct {
	Files []RenderedFile `json:"files"`
}

// renderSkeleton walks <pkgDir>/skeleton and renders every file as a Go
// template with strict missingkey=error. A ".tmpl" suffix is stripped from
// the output path. Files must be UTF-8; the total rendered size is capped
// at maxRenderedBytes. Returns files sorted by path.
func renderSkeleton(pkgDir string, data *RenderData) ([]RenderedFile, error) {
	root := filepath.Join(pkgDir, "skeleton")
	var out []RenderedFile
	total := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !utf8.Valid(raw) {
			return fmt.Errorf("scaffold: skeleton file %s is not UTF-8 (binary skeletons unsupported)", rel)
		}
		tmpl, err := template.New(rel).Option("missingkey=error").Parse(string(raw))
		if err != nil {
			return fmt.Errorf("scaffold: skeleton %s: parse: %w", rel, err)
		}
		var buf bytes.Buffer
		if err := tmpl.Execute(&buf, data); err != nil {
			return fmt.Errorf("scaffold: skeleton %s: render: %w", rel, err)
		}
		total += buf.Len()
		if total > maxRenderedBytes {
			return fmt.Errorf("scaffold: rendered skeleton exceeds %d bytes", maxRenderedBytes)
		}
		out = append(out, RenderedFile{Path: strings.TrimSuffix(rel, ".tmpl"), Content: buf.String()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("scaffold: %s: skeleton tree is empty", pkgDir)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// stepRendering renders the run's template skeleton into step.Result.
// Idempotent: a step whose Result already holds a rendered file list (a
// crash between step persist and the next step) returns done immediately.
func stepRendering(ctx context.Context, env *ExecEnv, rc *RunContext, step *types.ScaffoldRunStep) (bool, error) {
	if len(step.Result) > 0 && !bytes.Equal(bytes.TrimSpace(step.Result), []byte(`{}`)) {
		return true, nil
	}
	if env == nil || env.Templates == nil {
		return false, errors.New("scaffold: no template source configured")
	}
	name := strings.TrimPrefix(rc.Run.TemplateItemID, "template:")
	pkg, err := env.Templates.Get(ctx, name, rc.Run.TemplateVersion)
	if err != nil {
		return false, err
	}
	var values map[string]any
	if len(rc.Run.Values) > 0 {
		dec := json.NewDecoder(bytes.NewReader(rc.Run.Values))
		dec.UseNumber()
		if err := dec.Decode(&values); err != nil {
			return false, fmt.Errorf("scaffold: decode run values: %w", err)
		}
	}
	var tenant TenantContext
	if rc.Tenant != nil {
		tenant = *rc.Tenant
	}
	// Tenant-context binding (plan §6): manifests land in the component's
	// tenant-scoped namespace <org-slug>--<component-name>, never a shared
	// one. Deriving the component here (not per-skeleton) keeps every
	// rendered file on the same namespace.
	if tenant.Slug != "" {
		component, err := componentName(rc)
		if err != nil {
			return false, err
		}
		tenant.Namespace = componentNamespace(tenant.Slug, component)
	}
	data := &RenderData{Values: values, Tenant: tenant, Run: RunRef{ID: rc.Run.ID, Name: rc.Run.DisplayName}}
	files, err := renderSkeleton(pkg.Dir, data)
	if err != nil {
		return false, err
	}
	raw, err := json.Marshal(renderResult{Files: files})
	if err != nil {
		return false, err
	}
	step.Result = raw
	// Surface the rendered file count in run outputs for the UI; the
	// Service persists it with the step transition.
	var outputs map[string]any
	if len(rc.Run.Outputs) > 0 {
		_ = json.Unmarshal(rc.Run.Outputs, &outputs)
	}
	if outputs == nil {
		outputs = map[string]any{}
	}
	outputs["renderedFiles"] = len(files)
	if rc.Run.Outputs, err = json.Marshal(outputs); err != nil {
		return false, err
	}
	return true, nil
}
