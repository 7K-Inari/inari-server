// Package scaffold implements the Scaffolding / Software Templates module
// (M8, plan §4/§10): tenants browse template catalog items
// (source='template') at their effective version, submit wizard values
// validated against the version's JSON Schema, and poll the resulting
// scaffold run through its phases. This wave delivers the module core —
// store, service, HTTP API; the step runner / reconcile loop is W3.
package scaffold

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrTemplateNotFound is returned for unknown (or invisible) templates.
var ErrTemplateNotFound = errors.New("scaffold: template not found")

// ErrVersionNotFound is returned when the requested template version does
// not exist.
var ErrVersionNotFound = errors.New("scaffold: template version not found")

// stepNames is the canonical phase execution order (plan §3): phases map
// 1:1 to steps. Used to seed initial step rows and to order ListSteps.
var stepNames = []string{
	"rendering", "creating-repo", "creating-pipeline", "registering-catalog", "binding-rbac",
}

// newUUID returns a random v4 UUID (same scheme as tenantzonefactory).
func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

// Config carries the scaffold knobs (config.Config subset, M8.W1).
type Config struct {
	MaxAttempts int    // per-step attempt budget (default 5)
	GitOrg      string // git organization/owner receiving scaffolded repos
}

// --- Consumer-side seams (parent plan §10). Declared narrow here, wired
// in main.go; the runner (W3) and phase steps (W4) consume them. All are
// optional until then.

// GitProvider is the git backend subset scaffolding needs
// (orchestrator/gitprovider.Provider).
type GitProvider interface {
	EnsureRepo(ctx context.Context, repo string) (cloneURL string, err error)
	CommitFiles(ctx context.Context, repo, branch string, files []gitprovider.File, message string) (*gitprovider.Result, error)
}

// (CatalogUpserter is declared in template_source.go — the template sync
// and the run engine share it.)

// GroupBinder ensures the component's tenant team group and membership
// (tenancy.IdentityProvider subset).
type GroupBinder interface {
	EnsureGroup(ctx context.Context, path string) (groupID string, err error)
	AddGroupMember(ctx context.Context, groupID, userID string) error
}

// AppRegistrar enqueues agent commands (agentgateway.Queue subset) — the
// pull-model path for registering the component's ArgoCD Application.
type AppRegistrar interface {
	Enqueue(ctx context.Context, cmd *types.AgentCommand) error
}

// TemplateCatalog reads template catalog items at a tenant's effective
// version (catalog.Service).
type TemplateCatalog interface {
	ListVisible(ctx context.Context, orgID, clusterID string) ([]catalog.ItemView, error)
	EffectiveVersion(ctx context.Context, orgID, itemID, channel string) (string, error)
	GetVersion(ctx context.Context, itemID, version string) (*types.CatalogItemVersion, error)
	GetItemByID(ctx context.Context, itemID string) (*types.CatalogItem, error)
}

// Service orchestrates template browsing and scaffold run lifecycle: DB
// projection + audit + outbox in TXs, schema validation, idempotent
// creation.
type Service struct {
	db      *db.DB
	store   *Store
	audit   *audit.Store
	catalog TemplateCatalog
	cfg     Config
	log     *slog.Logger
	newID   func() string

	git       GitProvider
	upsert    CatalogUpserter
	groups    GroupBinder
	registrar AppRegistrar
}

// NewService builds the module service.
func NewService(d *db.DB, store *Store, auditStore *audit.Store, cat TemplateCatalog, cfg Config, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	return &Service{db: d, store: store, audit: auditStore, catalog: cat, cfg: cfg, log: log, newID: newUUID}
}

// WithExecutionSeams wires the backends the W3/W4 step engine consumes.
func (s *Service) WithExecutionSeams(git GitProvider, up CatalogUpserter, gb GroupBinder, ar AppRegistrar) *Service {
	s.git, s.upsert, s.groups, s.registrar = git, up, gb, ar
	return s
}

// TemplateSummary is the list-row view of a template (UI wizard browse).
type TemplateSummary struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Tags        []string `json:"tags,omitempty"`
	Version     string   `json:"version"`
}

// TemplateDetail adds the wizard schemas to the summary.
type TemplateDetail struct {
	TemplateSummary
	Schema   json.RawMessage `json:"schema,omitempty"`
	UISchema json.RawMessage `json:"uiSchema,omitempty"`
}

// ListTemplates returns the template catalog items visible to the tenant
// at their effective versions (plan §3).
func (s *Service) ListTemplates(ctx context.Context, orgID string) ([]TemplateSummary, error) {
	items, err := s.catalog.ListVisible(ctx, orgID, "")
	if err != nil {
		return nil, err
	}
	out := make([]TemplateSummary, 0, len(items))
	for i := range items {
		it := &items[i]
		if it.Source != types.CatalogSourceTemplate {
			continue
		}
		sum, err := s.summary(ctx, orgID, it)
		if err != nil {
			// An item with no resolvable version is not a usable template;
			// skip rather than fail the whole listing.
			s.log.Warn("scaffold: skipping template without resolvable version", "item", it.ID, "error", err)
			continue
		}
		out = append(out, *sum)
	}
	return out, nil
}

// GetTemplate returns one template's detail: summary + schema + optional
// uiSchema from the tenant's effective version.
func (s *Service) GetTemplate(ctx context.Context, orgID, name string) (*TemplateDetail, error) {
	it, err := s.resolveTemplate(ctx, orgID, name)
	if err != nil {
		return nil, err
	}
	sum, err := s.summary(ctx, orgID, it)
	if err != nil {
		return nil, err
	}
	ver, err := s.catalog.GetVersion(ctx, it.ID, sum.Version)
	if err != nil {
		return nil, fmt.Errorf("scaffold: template version %s: %w", sum.Version, err)
	}
	return &TemplateDetail{TemplateSummary: *sum, Schema: ver.Schema, UISchema: ver.UIHints}, nil
}

// summary projects one template item at the tenant's effective version.
func (s *Service) summary(ctx context.Context, orgID string, it *catalog.ItemView) (*TemplateSummary, error) {
	version, err := s.catalog.EffectiveVersion(ctx, orgID, it.ID, "")
	if err != nil {
		return nil, err
	}
	sum := &TemplateSummary{
		ID: it.ID, Name: it.Name, DisplayName: it.DisplayName,
		Description: it.Description, Version: version,
	}
	if ver, err := s.catalog.GetVersion(ctx, it.ID, version); err == nil {
		sum.Tags = parseTags(ver.Payload)
	}
	return sum, nil
}

// resolveTemplate finds the visible template item addressed by name (item
// name or ID), enforcing catalog visibility rules.
func (s *Service) resolveTemplate(ctx context.Context, orgID, name string) (*catalog.ItemView, error) {
	items, err := s.catalog.ListVisible(ctx, orgID, "")
	if err != nil {
		return nil, err
	}
	for i := range items {
		it := &items[i]
		if it.Source == types.CatalogSourceTemplate && (it.Name == name || it.ID == name) {
			return it, nil
		}
	}
	return nil, ErrTemplateNotFound
}

// parseTags extracts optional template tags from a version payload
// ({"manifest": {"tags": [...]}} written by the template sync); absent or
// malformed payloads yield nil.
func parseTags(payload json.RawMessage) []string {
	var p struct {
		Manifest struct {
			Tags []string `json:"tags"`
		} `json:"manifest"`
	}
	if len(payload) == 0 || json.Unmarshal(payload, &p) != nil {
		return nil
	}
	return p.Manifest.Tags
}

// FieldError is one wizard-values schema violation.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// ValidationError aggregates schema violations; the handler maps it to
// HTTP 422.
type ValidationError struct {
	Fields []FieldError
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("scaffold: values failed template schema validation (%d field errors)", len(e.Fields))
}

// validateValues checks wizard answers against the version's schema.json.
// An empty schema accepts anything. Schema compile errors are server
// faults (plain error); instance violations produce *ValidationError.
func validateValues(schemaRaw, values json.RawMessage) error {
	if len(schemaRaw) == 0 {
		return nil
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaRaw))
	if err != nil {
		return fmt.Errorf("scaffold: parse template schema: %w", err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", doc); err != nil {
		return fmt.Errorf("scaffold: load template schema: %w", err)
	}
	sch, err := compiler.Compile("schema.json")
	if err != nil {
		return fmt.Errorf("scaffold: compile template schema: %w", err)
	}
	var v any
	if len(values) > 0 {
		dec := json.NewDecoder(bytes.NewReader(values))
		dec.UseNumber()
		if err := dec.Decode(&v); err != nil {
			return &ValidationError{Fields: []FieldError{{Path: "", Message: "values is not valid JSON"}}}
		}
	}
	if v == nil {
		v = map[string]any{}
	}
	verr := sch.Validate(v)
	var schemaErr *jsonschema.ValidationError
	if errors.As(verr, &schemaErr) {
		return &ValidationError{Fields: collectFieldErrors(schemaErr)}
	}
	return verr
}

// collectFieldErrors flattens the validation error tree into leaf
// instance-location/message pairs.
func collectFieldErrors(ve *jsonschema.ValidationError) []FieldError {
	if len(ve.Causes) == 0 {
		path := ""
		for _, seg := range ve.InstanceLocation {
			path += "/" + seg
		}
		return []FieldError{{Path: path, Message: ve.Error()}}
	}
	var out []FieldError
	for _, c := range ve.Causes {
		out = append(out, collectFieldErrors(c)...)
	}
	return out
}

// idempotencyKey derives the dedup key for run creation: retries of the
// same wizard submit (same org, template, version, canonical values) map
// to the same run.
func idempotencyKey(orgID, templateName, version string, values json.RawMessage) string {
	h := sha256.New()
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(templateName))
	h.Write([]byte{0})
	h.Write([]byte(version))
	h.Write([]byte{0})
	h.Write(canonicalJSON(values))
	return hex.EncodeToString(h.Sum(nil))
}

// canonicalJSON normalizes JSON for hashing: a decode/re-marshal round
// trip sorts object keys and drops insignificant whitespace, so
// semantically equal values hash identically. Numbers decode as
// json.Number to preserve their literal form. Undecodable input (already
// rejected by validation upstream) is hashed as-is.
func canonicalJSON(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return raw
	}
	b, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return b
}

// CreateRun validates the wizard values against the template version's
// schema and persists the run plus its initial (pending) step rows with
// audit + outbox in one transaction. Retries with identical inputs return
// the existing run (existed=true) instead of creating a duplicate.
func (s *Service) CreateRun(ctx context.Context, actor, orgID, name, version, displayName string, values json.RawMessage) (*types.ScaffoldRun, []types.ScaffoldRunStep, bool, error) {
	it, err := s.resolveTemplate(ctx, orgID, name)
	if err != nil {
		return nil, nil, false, err
	}
	if version == "" {
		if version, err = s.catalog.EffectiveVersion(ctx, orgID, it.ID, ""); err != nil {
			return nil, nil, false, ErrTemplateNotFound
		}
	}
	ver, err := s.catalog.GetVersion(ctx, it.ID, version)
	if err != nil {
		return nil, nil, false, ErrVersionNotFound
	}
	if err := validateValues(ver.Schema, values); err != nil {
		return nil, nil, false, err
	}
	if displayName == "" {
		displayName = defaultDisplayName(it, values)
	}
	key := idempotencyKey(orgID, it.Name, version, values)
	run := &types.ScaffoldRun{
		ID: "run:" + s.newID(), OrgID: orgID, TemplateItemID: it.ID,
		TemplateVersion: version, DisplayName: displayName, Values: values,
		Phase: types.ScaffoldPhasePending, IdempotencyKey: key, CreatedBy: actor,
	}
	steps := make([]types.ScaffoldRunStep, 0, len(stepNames))
	for _, n := range stepNames {
		steps = append(steps, types.ScaffoldRunStep{
			RunID: run.ID, Name: n, State: types.ScaffoldStepPending, MaxAttempts: s.cfg.MaxAttempts,
		})
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateRun(ctx, tx, run, steps); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "scaffold.run_created",
			ObjectType: "scaffold_run", ObjectID: run.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"template":%q,"version":%q,"displayName":%q}`, it.Name, version, displayName)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventScaffoldRunCreated, types.ScaffoldRunPayload{
			OrgID: orgID, RunID: run.ID, TemplateName: it.Name, Version: version, Phase: string(run.Phase),
		})
	})
	if errors.Is(err, ErrIdempotencyConflict) {
		existing, err := s.store.GetRunByIdempotencyKey(ctx, s.db.Pool, orgID, key)
		if err != nil {
			return nil, nil, false, err
		}
		existingSteps, err := s.store.ListSteps(ctx, s.db.Pool, existing.ID)
		if err != nil {
			return nil, nil, false, err
		}
		return existing, existingSteps, true, nil
	}
	if err != nil {
		return nil, nil, false, err
	}
	return run, steps, false, nil
}

// defaultDisplayName derives a run display name from the wizard "name"
// answer, falling back to the template name.
func defaultDisplayName(it *catalog.ItemView, values json.RawMessage) string {
	var v struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(values, &v) == nil && v.Name != "" {
		return v.Name
	}
	return it.Name
}

// GetRun returns one run with its steps (org-scoped).
func (s *Service) GetRun(ctx context.Context, orgID, runID string) (*types.ScaffoldRun, []types.ScaffoldRunStep, error) {
	run, err := s.store.GetRun(ctx, s.db.Pool, orgID, runID)
	if err != nil {
		return nil, nil, err
	}
	steps, err := s.store.ListSteps(ctx, s.db.Pool, run.ID)
	if err != nil {
		return nil, nil, err
	}
	return run, steps, nil
}

// TemplateNameForRun resolves the run's catalog item name for the API
// contract (templateName).
func (s *Service) TemplateNameForRun(ctx context.Context, run *types.ScaffoldRun) string {
	item, err := s.catalog.GetItemByID(ctx, run.TemplateItemID)
	if err != nil {
		return run.TemplateItemID
	}
	return item.Name
}

// CancelRun raises the cooperative cancel flag (plan §5.4): the reconcile
// loop checks it before each step; already-created outputs are retained.
// Cancelling a terminal run is a conflict; cancelling twice is a no-op.
func (s *Service) CancelRun(ctx context.Context, actor, orgID, runID string) error {
	run, err := s.store.GetRun(ctx, s.db.Pool, orgID, runID)
	if err != nil {
		return err
	}
	if run.Phase == types.ScaffoldPhaseCompleted || run.Phase == types.ScaffoldPhaseFailed {
		return ErrInvalidState
	}
	if run.CancelledAt != nil {
		return nil
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetCancelled(ctx, tx, run.ID); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "scaffold.run_cancelled",
			ObjectType: "scaffold_run", ObjectID: run.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"phase":%q}`, run.Phase)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventScaffoldRunCancelled, types.ScaffoldRunPayload{
			OrgID: orgID, RunID: run.ID, Version: run.TemplateVersion, Phase: string(run.Phase),
		})
	})
}
