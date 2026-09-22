// Package extensionhost implements the Extension Host module (plan §5.8):
// backend plugins run as isolated sidecar processes verified via the
// inari-plugin-sdk handshake (protocol version + identity + checksum), and
// their HTTP endpoints are exposed through the authenticated reverse-proxy
// path /api/extensions/<name>/* with fine-grained authz (extension invoke).
package extensionhost

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// ErrNotFound is returned for unknown extensions.
var ErrNotFound = errors.New("extensionhost: extension not found")

// ErrInvalidInput is returned for malformed registration requests.
var ErrInvalidInput = errors.New("extensionhost: invalid input")

// ErrConflict is returned when a concurrent registration creates the same
// extension row first (unique name); the caller should retry as an upsert.
var ErrConflict = errors.New("extensionhost: extension name conflict")

// ErrChecksumMismatch is returned when the plugin binary does not match the
// registered sha256 checksum.
var ErrChecksumMismatch = errors.New("extensionhost: checksum mismatch")

// ErrProtocolVersion is returned when the plugin reports an unsupported
// contract protocol version.
var ErrProtocolVersion = errors.New("extensionhost: unsupported protocol version")

// ErrPluginIdentity is returned when the plugin-reported name/version does
// not match the registry record.
var ErrPluginIdentity = errors.New("extensionhost: plugin identity mismatch")

// SupportedProtocolVersion is the plugin contract version this control plane
// speaks. The value must equal the proto contract version reported in
// PluginInfo.api_version (proto/inari/plugin/v1: "e.g. inari.plugin.v1") —
// not the go-plugin wire protocol version ("1"); confusing the two rejects
// every SDK-based plugin at handshake.
const SupportedProtocolVersion = "inari.plugin.v1"

// Store persists extension registry rows.
type Store struct{}

func NewStore() *Store { return &Store{} }

const extCols = `id, COALESCE(org_id, ''), name, version, kind, manifest, ui, endpoint, checksum, state, created_at, updated_at`

func scanExtension(row interface{ Scan(...any) error }) (*types.Extension, error) {
	var e types.Extension
	var ui json.RawMessage
	err := row.Scan(&e.ID, &e.OrgID, &e.Name, &e.Version, &e.Kind, &e.Manifest, &ui,
		&e.Endpoint, &e.Checksum, &e.State, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if len(ui) > 0 && string(ui) != "null" {
		var d types.UiExtensionDescriptor
		if err := json.Unmarshal(ui, &d); err != nil {
			return nil, fmt.Errorf("extensionhost: decode ui descriptor: %w", err)
		}
		e.Ui = &d
	}
	return &e, nil
}

func (s *Store) create(ctx context.Context, q db.Querier, e *types.Extension) error {
	const sql = `INSERT INTO extensions (id, org_id, name, version, kind, manifest, endpoint, checksum)
	             VALUES ($1, NULLIF($2,''), $3, $4, $5, $6, $7, $8)
	             RETURNING state, created_at, updated_at`
	return q.QueryRow(ctx, sql, e.ID, e.OrgID, e.Name, e.Version, e.Kind, e.Manifest, e.Endpoint, e.Checksum).
		Scan(&e.State, &e.CreatedAt, &e.UpdatedAt)
}

func (s *Store) get(ctx context.Context, q db.Querier, id string) (*types.Extension, error) {
	e, err := scanExtension(q.QueryRow(ctx, `SELECT `+extCols+` FROM extensions WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *Store) getByName(ctx context.Context, q db.Querier, name string) (*types.Extension, error) {
	e, err := scanExtension(q.QueryRow(ctx, `SELECT `+extCols+` FROM extensions WHERE name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return e, err
}

func (s *Store) list(ctx context.Context, q db.Querier, orgID string) ([]types.Extension, error) {
	rows, err := q.Query(ctx, `SELECT `+extCols+` FROM extensions WHERE org_id = $1 ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Extension
	for rows.Next() {
		e, err := scanExtension(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (s *Store) setState(ctx context.Context, q db.Querier, id, state string) error {
	const sql = `UPDATE extensions SET state = $2, updated_at = now() WHERE id = $1`
	_, err := q.Exec(ctx, sql, id, state)
	return err
}

func (s *Store) touchVersion(ctx context.Context, q db.Querier, id, version string) error {
	const sql = `UPDATE extensions SET version = $2, updated_at = now() WHERE id = $1`
	_, err := q.Exec(ctx, sql, id, version)
	return err
}

func (s *Store) setUi(ctx context.Context, q db.Querier, id string, ui json.RawMessage) error {
	const sql = `UPDATE extensions SET ui = $2, updated_at = now() WHERE id = $1`
	_, err := q.Exec(ctx, sql, id, ui)
	return err
}

func (s *Store) listUi(ctx context.Context, q db.Querier, orgID string) ([]types.Extension, error) {
	rows, err := q.Query(ctx, `SELECT `+extCols+` FROM extensions WHERE org_id = $1 AND ui IS NOT NULL ORDER BY name`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Extension
	for rows.Next() {
		e, err := scanExtension(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *e)
	}
	return out, rows.Err()
}

func (s *Store) delete(ctx context.Context, q db.Querier, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM extensions WHERE id = $1`, id)
	return err
}

// Service is the extension registry: registration, lookup, and state
// transitions with audit + outbox in one TX.
type Service struct {
	db    *db.DB
	store *Store
	audit *audit.Store
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store) *Service {
	return &Service{db: d, store: store, audit: auditStore}
}

// RegisterInput is one extension registration. Endpoint is the sidecar HTTP
// base URL (dial mode); Checksum is the expected sha256 of the plugin
// artifact (hex), verified before the extension may go ready.
type RegisterInput struct {
	OrgID    string
	Name     string
	Version  string
	Kind     string
	Manifest json.RawMessage
	Endpoint string
	Checksum string
}

// Register adds an extension in pending state and emits
// extension.registered (drives the FGA parent tuple).
func (s *Service) Register(ctx context.Context, actor string, in RegisterInput) (*types.Extension, error) {
	if in.Name == "" || in.Version == "" {
		return nil, fmt.Errorf("%w: name and version are required", ErrInvalidInput)
	}
	if in.OrgID == "" {
		return nil, fmt.Errorf("%w: orgID is required", ErrInvalidInput)
	}
	kind := in.Kind
	if kind == "" {
		kind = types.ExtensionKindBackend
	}
	if kind != types.ExtensionKindBackend {
		return nil, fmt.Errorf("%w: kind must be backend", ErrInvalidInput)
	}
	manifest := in.Manifest
	if len(manifest) == 0 {
		manifest = json.RawMessage(`{}`)
	}
	e := &types.Extension{
		ID: "extension:" + newUUID(), OrgID: in.OrgID, Name: in.Name, Version: in.Version,
		Kind: kind, Manifest: manifest, Endpoint: in.Endpoint, Checksum: in.Checksum,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.create(ctx, tx, e); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: in.OrgID, Actor: actor, Action: "extension.registered",
			ObjectType: "extension", ObjectID: e.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, in.OrgID, types.EventExtensionRegistered, types.ExtensionPayload{
			OrgID: in.OrgID, ExtensionID: e.ID, Name: e.Name,
		})
	})
	if err != nil {
		return nil, err
	}
	return e, nil
}

// Get returns one extension scoped to the org (404 on mismatch).
func (s *Service) Get(ctx context.Context, orgID, id string) (*types.Extension, error) {
	e, err := s.store.get(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if e.OrgID != orgID {
		return nil, ErrNotFound
	}
	return e, nil
}

// GetByName returns one extension by its unique name (proxy path lookup).
func (s *Service) GetByName(ctx context.Context, name string) (*types.Extension, error) {
	return s.store.getByName(ctx, s.db.Pool, name)
}

// List returns the org's extensions.
func (s *Service) List(ctx context.Context, orgID string) ([]types.Extension, error) {
	return s.store.list(ctx, s.db.Pool, orgID)
}

// SetState transitions the extension state (supervisor-driven) with audit +
// outbox on change. No-op when the state is unchanged.
func (s *Service) SetState(ctx context.Context, actor, id, state string) error {
	e, err := s.store.get(ctx, s.db.Pool, id)
	if err != nil {
		return err
	}
	if e.State == state {
		return nil
	}
	switch state {
	case types.ExtensionStatePending, types.ExtensionStateReady, types.ExtensionStateDegraded, types.ExtensionStateStopped:
	default:
		return fmt.Errorf("%w: unknown state %q", ErrInvalidInput, state)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.setState(ctx, tx, id, state); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: e.OrgID, Actor: actor, Action: "extension.state_changed",
			ObjectType: "extension", ObjectID: id,
			Payload: json.RawMessage(fmt.Sprintf(`{"state":%q}`, state)),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, e.OrgID, types.EventExtensionStateChanged, types.ExtensionPayload{
			OrgID: e.OrgID, ExtensionID: id, Name: e.Name, State: state,
		})
	})
}

// Verify runs the SDK handshake against the registered endpoint and moves
// the extension to ready (or degraded on failure). Exec-mode artifact
// checksums are verified by the supervisor at spawn; dial-mode deployments
// verify identity + protocol version here.
func (s *Service) Verify(ctx context.Context, actor, orgID, id string) (*types.Extension, error) {
	e, err := s.Get(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if e.Endpoint == "" {
		return nil, fmt.Errorf("%w: endpoint is required for verification", ErrInvalidInput)
	}
	if _, err := VerifyHandshake(ctx, e.Endpoint, e); err != nil {
		if serr := s.SetState(ctx, actor, id, types.ExtensionStateDegraded); serr != nil {
			return nil, serr
		}
		return nil, err
	}
	if err := s.SetState(ctx, actor, id, types.ExtensionStateReady); err != nil {
		return nil, err
	}
	return s.Get(ctx, orgID, id)
}

// Unregister removes the extension and its FGA parent tuple (via outbox).
func (s *Service) Unregister(ctx context.Context, actor, orgID, id string) error {
	if _, err := s.Get(ctx, orgID, id); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.delete(ctx, tx, id); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "extension.unregistered",
			ObjectType: "extension", ObjectID: id,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventExtensionUnregistered, types.ExtensionPayload{
			OrgID: orgID, ExtensionID: id,
		})
	})
}

// validUiSlotKinds is the blueprint enum (§8.4) shared with
// inari-ui-plugin-sdk SlotKind.
var validUiSlotKinds = map[string]bool{
	types.UiSlotNavItem:        true,
	types.UiSlotCatalogCard:    true,
	types.UiSlotClusterTab:     true,
	types.UiSlotInstanceAction: true,
	types.UiSlotFormWidget:     true,
	types.UiSlotPage:           true,
}

// RegisterUiInput is one UI extension registration. Exactly one of
// RemoteEntry (external HTTPS URL) or RemoteEntryOci (oras artifact ref)
// must be set; the control plane serves remoteEntry.js itself from either.
type RegisterUiInput struct {
	OrgID              string
	Name               string
	Version            string
	RemoteEntry        string
	RemoteEntryOci     string
	Checksum           string
	Title              string
	Description        string
	RequiredPermission string
	Slots              []types.UiSlotDescriptor
	Enabled            *bool // nil defaults to true
}

func validateUiInput(in RegisterUiInput) error {
	if in.Name == "" || in.Version == "" {
		return fmt.Errorf("%w: name and version are required", ErrInvalidInput)
	}
	if in.OrgID == "" {
		return fmt.Errorf("%w: orgID is required", ErrInvalidInput)
	}
	if (in.RemoteEntry == "") == (in.RemoteEntryOci == "") {
		return fmt.Errorf("%w: exactly one of remoteEntry or remoteEntryOci is required", ErrInvalidInput)
	}
	for _, s := range in.Slots {
		if !validUiSlotKinds[s.Kind] {
			return fmt.Errorf("%w: unknown slot kind %q", ErrInvalidInput, s.Kind)
		}
		if s.Name == "" {
			return fmt.Errorf("%w: slot name is required", ErrInvalidInput)
		}
	}
	return nil
}

// RegisterUi upserts the UI descriptor on the extension named in.Name within
// the org: an existing row (e.g. a paired backend, spec.kinds [backend, ui])
// gains the descriptor; otherwise a new ui-kind row is created directly in
// ready state (there is no handshake for UI remotes). Audit always; the FGA
// parent tuple is only emitted on row creation.
func (s *Service) RegisterUi(ctx context.Context, actor string, in RegisterUiInput) (*types.Extension, error) {
	if err := validateUiInput(in); err != nil {
		return nil, err
	}
	e, err := s.store.getByName(ctx, s.db.Pool, in.Name)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	created := errors.Is(err, ErrNotFound)
	// Enabled defaults to true on creation; on update an omitted flag
	// preserves the stored value so re-registrations don't silently
	// re-enable a disabled extension.
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	} else if !created && e.Ui != nil {
		enabled = e.Ui.Enabled
	}
	desc := types.UiExtensionDescriptor{
		RemoteEntry: in.RemoteEntry, RemoteEntryOci: in.RemoteEntryOci, Checksum: in.Checksum,
		Title: in.Title, Description: in.Description, RequiredPermission: in.RequiredPermission,
		Slots: in.Slots, Enabled: enabled,
	}
	if desc.Slots == nil {
		desc.Slots = []types.UiSlotDescriptor{}
	}
	uiJSON, err := json.Marshal(desc)
	if err != nil {
		return nil, err
	}
	if created {
		e = &types.Extension{
			ID: "extension:" + newUUID(), OrgID: in.OrgID, Name: in.Name, Version: in.Version,
			Kind: types.ExtensionKindUI, Manifest: json.RawMessage(`{}`),
		}
	}
	if e.OrgID != in.OrgID {
		return nil, ErrNotFound
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if created {
			if err := s.store.create(ctx, tx, e); err != nil {
				if isUniqueViolation(err) {
					return ErrConflict
				}
				return err
			}
			if err := s.store.setState(ctx, tx, e.ID, types.ExtensionStateReady); err != nil {
				return err
			}
		} else if err := s.store.touchVersion(ctx, tx, e.ID, in.Version); err != nil {
			return err
		}
		if err := s.store.setUi(ctx, tx, e.ID, uiJSON); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: in.OrgID, Actor: actor, Action: "extension.ui_registered",
			ObjectType: "extension", ObjectID: e.ID,
			Payload: json.RawMessage(fmt.Sprintf(`{"name":%q,"version":%q}`, in.Name, in.Version)),
		}); err != nil {
			return err
		}
		if !created {
			return nil
		}
		return audit.AppendOutbox(ctx, tx, in.OrgID, types.EventExtensionRegistered, types.ExtensionPayload{
			OrgID: in.OrgID, ExtensionID: e.ID, Name: e.Name,
		})
	})
	if err != nil {
		return nil, err
	}
	return s.store.get(ctx, s.db.Pool, e.ID)
}

// GetUi returns the org's extension with a UI descriptor by name (404 on
// mismatch or missing UI).
func (s *Service) GetUi(ctx context.Context, orgID, name string) (*types.Extension, error) {
	e, err := s.store.getByName(ctx, s.db.Pool, name)
	if err != nil {
		return nil, err
	}
	if e.OrgID != orgID || e.Ui == nil {
		return nil, ErrNotFound
	}
	return e, nil
}

// ListUi returns the org's extensions that carry a UI descriptor.
func (s *Service) ListUi(ctx context.Context, orgID string) ([]types.Extension, error) {
	return s.store.listUi(ctx, s.db.Pool, orgID)
}

// UnregisterUi clears the UI descriptor. When the row has no backend half
// (kind=ui) it is deleted entirely and the FGA parent tuple retracted; a
// paired backend row keeps its registration.
func (s *Service) UnregisterUi(ctx context.Context, actor, orgID, name string) error {
	e, err := s.GetUi(ctx, orgID, name)
	if err != nil {
		return err
	}
	removeRow := e.Kind == types.ExtensionKindUI
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if removeRow {
			if err := s.store.delete(ctx, tx, e.ID); err != nil {
				return err
			}
		} else if err := s.store.setUi(ctx, tx, e.ID, nil); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "extension.ui_unregistered",
			ObjectType: "extension", ObjectID: e.ID,
		}); err != nil {
			return err
		}
		if !removeRow {
			return nil
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventExtensionUnregistered, types.ExtensionPayload{
			OrgID: orgID, ExtensionID: e.ID,
		})
	})
}

// VerifyChecksum reports whether the artifact at path hashes to the expected
// sha256 (hex). An empty expected checksum means "unverified" and passes —
// checksum pinning is opt-in per registration (dial-mode sidecars deployed
// by infra have no local artifact to hash).
func VerifyChecksum(path, expectedHex string) error {
	if expectedHex == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("extensionhost: open artifact: %w", err)
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("extensionhost: hash artifact: %w", err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != expectedHex {
		return fmt.Errorf("%w: got %s want %s", ErrChecksumMismatch, got, expectedHex)
	}
	return nil
}

func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}
