// Package notifications implements the Notifications module (plan §5.2):
// tenant-configured Slack/webhook endpoints subscribed to outbox events
// (approvals, capability changes, provisioning completion), best-effort
// delivery with a recorded notification_deliveries row per attempt.
package notifications

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrEndpointNotFound = errors.New("notification endpoint not found")
	ErrInvalidKind      = errors.New("invalid endpoint kind (slack|webhook)")
	ErrInvalidURL       = errors.New("endpoint URL must be http(s)")
	ErrInvalidEvent     = errors.New("unknown event type in events filter")
	ErrNameRequired     = errors.New("endpoint name is required")
)

// maxAttempts caps RetryFailed redelivery.
const maxAttempts = 5

// subscribedEvents is the set of outbox event types the module handles.
var subscribedEvents = []string{
	types.EventApprovalRequested,
	types.EventApprovalDecided,
	types.EventApprovalCancelled,
	types.EventApprovalExpired,
	types.EventCapabilitiesIngested,
	types.EventInstanceStatus,
	types.EventDeployRequested,
	types.EventInstanceUpgraded,
}

func knownEvent(t string) bool {
	for _, e := range subscribedEvents {
		if e == t {
			return true
		}
	}
	return false
}

// matchesEvents reports whether an endpoint subscribes to eventType; an
// empty events list means all events.
func matchesEvents(ep *types.NotificationEndpoint, eventType string) bool {
	if len(ep.Events) == 0 {
		return true
	}
	for _, e := range ep.Events {
		if e == eventType {
			return true
		}
	}
	return false
}

// Store is the PostgreSQL projection of notification state.
type Store struct{}

func NewStore() *Store { return &Store{} }

const endpointCols = `id, org_id, name, kind, url, secret, events, enabled, created_at`

func scanEndpoint(row interface{ Scan(...any) error }) (*types.NotificationEndpoint, error) {
	var ep types.NotificationEndpoint
	err := row.Scan(&ep.ID, &ep.OrgID, &ep.Name, &ep.Kind, &ep.URL, &ep.Secret, &ep.Events, &ep.Enabled, &ep.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &ep, nil
}

func (s *Store) CreateEndpoint(ctx context.Context, q db.Querier, ep *types.NotificationEndpoint) error {
	const sql = `INSERT INTO notification_endpoints (id, org_id, name, kind, url, secret, events, enabled)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING ` + endpointCols
	out, err := scanEndpoint(q.QueryRow(ctx, sql, ep.ID, ep.OrgID, ep.Name, ep.Kind, ep.URL, ep.Secret, ep.Events, ep.Enabled))
	if err != nil {
		return err
	}
	*ep = *out
	return nil
}

func (s *Store) GetEndpoint(ctx context.Context, q db.Querier, id string) (*types.NotificationEndpoint, error) {
	const sql = `SELECT ` + endpointCols + ` FROM notification_endpoints WHERE id = $1`
	ep, err := scanEndpoint(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEndpointNotFound
	}
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func (s *Store) ListEndpoints(ctx context.Context, q db.Querier, orgID string) ([]types.NotificationEndpoint, error) {
	const sql = `SELECT ` + endpointCols + ` FROM notification_endpoints WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.NotificationEndpoint
	for rows.Next() {
		ep, err := scanEndpoint(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *ep)
	}
	return out, rows.Err()
}

func (s *Store) UpdateEndpoint(ctx context.Context, q db.Querier, ep *types.NotificationEndpoint) error {
	const sql = `UPDATE notification_endpoints SET name=$2, url=$3, secret=$4, events=$5, enabled=$6
	             WHERE id=$1 RETURNING ` + endpointCols
	out, err := scanEndpoint(q.QueryRow(ctx, sql, ep.ID, ep.Name, ep.URL, ep.Secret, ep.Events, ep.Enabled))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrEndpointNotFound
	}
	if err != nil {
		return err
	}
	*ep = *out
	return nil
}

func (s *Store) DeleteEndpoint(ctx context.Context, q db.Querier, id string) error {
	const sql = `DELETE FROM notification_endpoints WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrEndpointNotFound
	}
	return nil
}

const deliveryCols = `id, endpoint_id, event_type, payload, status, attempts, last_error, created_at, delivered_at`

func scanDelivery(row interface{ Scan(...any) error }) (*types.NotificationDelivery, error) {
	var d types.NotificationDelivery
	err := row.Scan(&d.ID, &d.EndpointID, &d.EventType, &d.Payload, &d.Status, &d.Attempts, &d.LastError, &d.CreatedAt, &d.DeliveredAt)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// InsertDelivery records a delivery attempt (attempts is incremented).
func (s *Store) InsertDelivery(ctx context.Context, q db.Querier, d *types.NotificationDelivery) error {
	const sql = `INSERT INTO notification_deliveries (endpoint_id, event_type, payload, status, attempts, last_error, delivered_at)
	             VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING ` + deliveryCols
	out, err := scanDelivery(q.QueryRow(ctx, sql, d.EndpointID, d.EventType, d.Payload, d.Status, d.Attempts, d.LastError, d.DeliveredAt))
	if err != nil {
		return err
	}
	*d = *out
	return nil
}

// ListFailed returns failed deliveries under the attempt cap, oldest first.
func (s *Store) ListFailed(ctx context.Context, q db.Querier, limit int) ([]types.NotificationDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	const sql = `SELECT ` + deliveryCols + ` FROM notification_deliveries
	             WHERE status = $1 AND attempts < $2 ORDER BY created_at LIMIT $3`
	rows, err := q.Query(ctx, sql, types.DeliveryStatusFailed, maxAttempts, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.NotificationDelivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *d)
	}
	return out, rows.Err()
}

// MarkRetry updates a delivery row after a retry attempt.
func (s *Store) MarkRetry(ctx context.Context, q db.Querier, d *types.NotificationDelivery) error {
	const sql = `UPDATE notification_deliveries SET status=$2, attempts=$3, last_error=$4, delivered_at=$5 WHERE id=$1`
	_, err := q.Exec(ctx, sql, d.ID, d.Status, d.Attempts, d.LastError, d.DeliveredAt)
	return err
}

// Service implements audit.Handler and endpoint CRUD.
type Service struct {
	db      *db.DB
	store   *Store
	audit   *audit.Store
	slack   *SlackSender
	webhook *WebhookSender
}

func NewService(d *db.DB, store *Store, auditStore *audit.Store, slack *SlackSender, webhook *WebhookSender) *Service {
	if store == nil {
		store = NewStore()
	}
	if auditStore == nil {
		auditStore = audit.NewStore()
	}
	if slack == nil {
		slack = NewSlackSender(nil)
	}
	if webhook == nil {
		webhook = NewWebhookSender(nil)
	}
	return &Service{db: d, store: store, audit: auditStore, slack: slack, webhook: webhook}
}

// EventTypes implements audit.Handler.
func (s *Service) EventTypes() []string { return subscribedEvents }

func (s *Service) senderFor(kind string) (Sender, error) {
	return SenderFor(kind, s.slack, s.webhook)
}

// Handle implements audit.Handler: fan out to subscribed enabled endpoints
// and record one delivery row per attempt. Delivery failures are recorded
// and logged but never fail the event — other outbox handlers still run.
func (s *Service) Handle(ctx context.Context, ev *types.OutboxEvent) error {
	endpoints, err := s.store.ListEndpoints(ctx, s.db.Pool, ev.OrgID)
	if err != nil {
		return fmt.Errorf("notifications: list endpoints: %w", err)
	}
	msg := Message{EventType: ev.EventType, Payload: ev.Payload, Text: formatMessage(ev)}
	for i := range endpoints {
		ep := &endpoints[i]
		if !ep.Enabled || !matchesEvents(ep, ev.EventType) {
			continue
		}
		s.deliver(ctx, ep, msg)
	}
	return nil
}

// deliver sends one message and records the delivery row.
func (s *Service) deliver(ctx context.Context, ep *types.NotificationEndpoint, msg Message) {
	d := &types.NotificationDelivery{
		EndpointID: ep.ID,
		EventType:  msg.EventType,
		Payload:    msg.Payload,
		Attempts:   1,
	}
	snd, err := s.senderFor(ep.Kind)
	if err == nil {
		err = snd.Send(ctx, ep, msg)
	}
	if err != nil {
		d.Status = types.DeliveryStatusFailed
		d.LastError = err.Error()
		slog.Warn("notification delivery failed",
			"endpoint", ep.ID, "event", msg.EventType, "error", err)
	} else {
		d.Status = types.DeliveryStatusDelivered
		now := time.Now()
		d.DeliveredAt = &now
	}
	if err := s.store.InsertDelivery(ctx, s.db.Pool, d); err != nil {
		slog.Error("notifications: record delivery", "endpoint", ep.ID, "error", err)
	}
}

// RetryFailed re-attempts failed deliveries under the attempt cap; for a
// future background loop.
func (s *Service) RetryFailed(ctx context.Context, limit int) (retried int, err error) {
	failed, err := s.store.ListFailed(ctx, s.db.Pool, limit)
	if err != nil {
		return 0, err
	}
	for i := range failed {
		d := &failed[i]
		ep, err := s.store.GetEndpoint(ctx, s.db.Pool, d.EndpointID)
		if err != nil {
			slog.Warn("notifications: retry: endpoint lookup", "endpoint", d.EndpointID, "error", err)
			continue
		}
		d.Attempts++
		snd, serr := s.senderFor(ep.Kind)
		if serr == nil {
			serr = snd.Send(ctx, ep, Message{EventType: d.EventType, Payload: d.Payload, Text: "retry: " + d.EventType})
		}
		if serr != nil {
			d.Status = types.DeliveryStatusFailed
			d.LastError = serr.Error()
		} else {
			d.Status = types.DeliveryStatusDelivered
			d.LastError = ""
			now := time.Now()
			d.DeliveredAt = &now
		}
		if err := s.store.MarkRetry(ctx, s.db.Pool, d); err != nil {
			slog.Error("notifications: retry: mark", "delivery", d.ID, "error", err)
			continue
		}
		retried++
	}
	return retried, nil
}

// EndpointInput carries caller-supplied endpoint fields for create/update.
type EndpointInput struct {
	Name    string
	Kind    string
	URL     string
	Secret  string
	Events  []string
	Enabled *bool
}

func validateEndpoint(in *EndpointInput, kind string) error {
	if strings.TrimSpace(in.Name) == "" {
		return ErrNameRequired
	}
	k := kind
	if k == "" {
		k = in.Kind
	}
	if k != types.NotificationKindSlack && k != types.NotificationKindWebhook {
		return ErrInvalidKind
	}
	u, err := url.Parse(in.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ErrInvalidURL
	}
	if u.User != nil {
		return fmt.Errorf("%w: credentials in URL are not allowed", ErrInvalidURL)
	}
	if err := rejectPrivateHost(u.Hostname()); err != nil {
		return err
	}
	for _, e := range in.Events {
		if !knownEvent(e) {
			return fmt.Errorf("%w: %s", ErrInvalidEvent, e)
		}
	}
	return nil
}

// AllowPrivateEndpoints disables the SSRF private-address check on endpoint
// URLs. TESTS ONLY — httptest servers listen on loopback.
var AllowPrivateEndpoints = false

// rejectPrivateHost blocks endpoints pointing at loopback, private,
// link-local, or otherwise non-public addresses (SSRF guard). Literal IPs
// are checked directly; hostnames are resolved and every returned address
// must be public.
func rejectPrivateHost(host string) error {
	if AllowPrivateEndpoints {
		return nil
	}
	if host == "" {
		return ErrInvalidURL
	}
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return fmt.Errorf("%w: endpoint must not target a private/reserved address", ErrInvalidURL)
		}
		return nil
	}
	ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", host)
	if err != nil {
		return fmt.Errorf("%w: cannot resolve endpoint host %q", ErrInvalidURL, host)
	}
	for _, ip := range ips {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
			return fmt.Errorf("%w: endpoint host %q resolves to a private/reserved address", ErrInvalidURL, host)
		}
	}
	return nil
}

// CreateEndpoint validates and persists a new endpoint (one TX: row + audit).
func (s *Service) CreateEndpoint(ctx context.Context, actor, orgID string, in EndpointInput) (*types.NotificationEndpoint, error) {
	if err := validateEndpoint(&in, ""); err != nil {
		return nil, err
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	ep := &types.NotificationEndpoint{
		ID:      "nep:" + newUUID(),
		OrgID:   orgID,
		Name:    in.Name,
		Kind:    in.Kind,
		URL:     in.URL,
		Secret:  in.Secret,
		Events:  in.Events,
		Enabled: enabled,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateEndpoint(ctx, tx, ep); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "notification_endpoint.created", ObjectType: "notification_endpoint", ObjectID: ep.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func (s *Service) ListEndpoints(ctx context.Context, orgID string) ([]types.NotificationEndpoint, error) {
	return s.store.ListEndpoints(ctx, s.db.Pool, orgID)
}

// GetEndpoint returns the endpoint if it belongs to orgID.
func (s *Service) GetEndpoint(ctx context.Context, orgID, id string) (*types.NotificationEndpoint, error) {
	ep, err := s.store.GetEndpoint(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if ep.OrgID != orgID {
		return nil, ErrEndpointNotFound
	}
	return ep, nil
}

// UpdateEndpoint edits name/url/events/enabled (and secret when provided).
func (s *Service) UpdateEndpoint(ctx context.Context, actor, orgID, id string, in EndpointInput) (*types.NotificationEndpoint, error) {
	ep, err := s.GetEndpoint(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	if in.Name != "" {
		ep.Name = in.Name
	}
	if in.URL != "" {
		ep.URL = in.URL
	}
	if in.Secret != "" {
		ep.Secret = in.Secret
	}
	if in.Events != nil {
		ep.Events = in.Events
	}
	if in.Enabled != nil {
		ep.Enabled = *in.Enabled
	}
	if err := validateEndpoint(&EndpointInput{Name: ep.Name, URL: ep.URL, Events: ep.Events}, ep.Kind); err != nil {
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateEndpoint(ctx, tx, ep); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "notification_endpoint.updated", ObjectType: "notification_endpoint", ObjectID: ep.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return ep, nil
}

func (s *Service) DeleteEndpoint(ctx context.Context, actor, orgID, id string) error {
	if _, err := s.GetEndpoint(ctx, orgID, id); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeleteEndpoint(ctx, tx, id); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "notification_endpoint.deleted", ObjectType: "notification_endpoint", ObjectID: id,
		})
	})
}

// TestEndpoint sends a test message and records the delivery (row + audit).
func (s *Service) TestEndpoint(ctx context.Context, actor, orgID, id string) (*types.NotificationDelivery, error) {
	ep, err := s.GetEndpoint(ctx, orgID, id)
	if err != nil {
		return nil, err
	}
	msg := Message{
		EventType: "notification.test",
		Text:      fmt.Sprintf("Inari test notification for endpoint %q", ep.Name),
	}
	d := &types.NotificationDelivery{EndpointID: ep.ID, EventType: msg.EventType, Attempts: 1}
	d.Payload = []byte(`{}`)
	snd, serr := s.senderFor(ep.Kind)
	if serr == nil {
		serr = snd.Send(ctx, ep, msg)
	}
	if serr != nil {
		d.Status = types.DeliveryStatusFailed
		d.LastError = serr.Error()
	} else {
		d.Status = types.DeliveryStatusDelivered
		now := time.Now()
		d.DeliveredAt = &now
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.InsertDelivery(ctx, tx, d); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "notification_endpoint.tested", ObjectType: "notification_endpoint", ObjectID: ep.ID,
		})
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

// formatMessage builds the human-readable text for an outbox event.
func formatMessage(ev *types.OutboxEvent) string {
	p := ev.Payload
	switch ev.EventType {
	case types.EventApprovalRequested:
		var pl types.ApprovalPayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Approval requested for catalog item %s (approval %s)", pl.ItemID, pl.ApprovalID)
		}
	case types.EventApprovalDecided:
		var pl types.ApprovalPayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Approval %s for catalog item %s was %s", pl.ApprovalID, pl.ItemID, pl.State)
		}
	case types.EventApprovalCancelled:
		var pl types.ApprovalPayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Approval %s for catalog item %s was cancelled", pl.ApprovalID, pl.ItemID)
		}
	case types.EventApprovalExpired:
		var pl types.ApprovalPayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Approval %s for catalog item %s expired", pl.ApprovalID, pl.ItemID)
		}
	case types.EventCapabilitiesIngested:
		var pl types.CapabilitiesIngestedPayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Cluster %s capabilities updated (%d upserted, %d deleted)", pl.ClusterID, pl.Upserted, pl.Deleted)
		}
	case types.EventInstanceStatus:
		var pl types.InstancePayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Instance %s on cluster %s is now %s", pl.InstanceID, pl.ClusterID, pl.Health)
		}
	case types.EventDeployRequested:
		var pl types.DeployRequestedPayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Deploy of catalog item %s (version %s) requested on cluster %s", pl.ItemID, pl.Version, pl.ClusterID)
		}
	case types.EventInstanceUpgraded:
		var pl types.InstancePayload
		if unmarshalPayload(p, &pl) {
			return fmt.Sprintf("Instance %s on cluster %s upgraded to version %s", pl.InstanceID, pl.ClusterID, pl.Version)
		}
	}
	return fmt.Sprintf("Inari event %s", ev.EventType)
}

func unmarshalPayload(raw []byte, v any) bool {
	return json.Unmarshal(raw, v) == nil
}

func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
