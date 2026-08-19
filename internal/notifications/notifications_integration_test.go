//go:build integration

package notifications_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/notifications"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itDB(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	pg, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("inari"),
		postgres.WithUsername("inari"),
		postgres.WithPassword("inari"),
		testcontainers.WithWaitStrategy(wait.ForLog("database system is ready to accept connections").WithOccurrence(2)),
	)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	t.Cleanup(func() { _ = pg.Terminate(ctx) })
	url, err := pg.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	database, err := db.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := database.Pool.Exec(ctx,
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ('org:1','acme','Acme','kc-1')`); err != nil {
		t.Fatal(err)
	}
	return database
}

func newService(database *db.DB, slack *notifications.SlackSender, webhook *notifications.WebhookSender) *notifications.Service {
	notifications.AllowPrivateEndpoints = true // httptest servers listen on loopback
	return notifications.NewService(database, notifications.NewStore(), audit.NewStore(), slack, webhook)
}

func TestEndpointCRUD(t *testing.T) {
	database := itDB(t)
	svc := newService(database, nil, nil)
	ctx := context.Background()

	ep, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "alerts", Kind: types.NotificationKindWebhook, URL: "https://example.io/hook",
		Events: []string{types.EventApprovalRequested},
	})
	if err != nil {
		t.Fatal(err)
	}
	if ep.ID == "" || !ep.Enabled {
		t.Fatalf("bad endpoint: %+v", ep)
	}
	if _, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "bad", Kind: "pagerduty", URL: "https://example.io",
	}); err == nil {
		t.Fatal("expected kind validation error")
	}

	got, err := svc.GetEndpoint(ctx, "org:1", ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "alerts" {
		t.Fatalf("got %+v", got)
	}
	if _, err := svc.GetEndpoint(ctx, "org:other", ep.ID); err == nil {
		t.Fatal("expected not-found for foreign org")
	}

	list, err := svc.ListEndpoints(ctx, "org:1")
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v %d", err, len(list))
	}

	disabled := false
	up, err := svc.UpdateEndpoint(ctx, "user-1", "org:1", ep.ID, notifications.EndpointInput{
		Name: "alerts-2", Enabled: &disabled,
	})
	if err != nil {
		t.Fatal(err)
	}
	if up.Name != "alerts-2" || up.Enabled {
		t.Fatalf("update: %+v", up)
	}

	var actions []string
	rows, err := database.Pool.Query(ctx, `SELECT action FROM audit_events WHERE org_id='org:1' ORDER BY created_at`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a string
		_ = rows.Scan(&a)
		actions = append(actions, a)
	}
	rows.Close()
	if len(actions) != 3 || actions[0] != "notification_endpoint.created" || actions[1] != "notification_endpoint.updated" {
		t.Fatalf("audit actions: %v", actions)
	}

	if err := svc.DeleteEndpoint(ctx, "user-1", "org:1", ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GetEndpoint(ctx, "org:1", ep.ID); err == nil {
		t.Fatal("expected not-found after delete")
	}
}

func TestHandleDeliversAndRecords(t *testing.T) {
	database := itDB(t)
	var hits int32
	var lastBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		lastBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newService(database, nil, nil)
	ctx := context.Background()

	if _, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "hook", Kind: types.NotificationKindWebhook, URL: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}

	payload, _ := json.Marshal(types.ApprovalPayload{OrgID: "org:1", ApprovalID: "ap-1", ItemID: "postgres"})
	ev := &types.OutboxEvent{ID: 1, OrgID: "org:1", EventType: types.EventApprovalRequested, Payload: payload}
	if err := svc.Handle(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("expected 1 delivery, got %d", hits)
	}
	var env struct {
		Event string `json:"event"`
		Text  string `json:"text"`
	}
	if err := json.Unmarshal(lastBody, &env); err != nil {
		t.Fatal(err)
	}
	if env.Event != types.EventApprovalRequested || env.Text == "" {
		t.Fatalf("bad envelope: %s", lastBody)
	}

	var status string
	var attempts int
	err := database.Pool.QueryRow(ctx,
		`SELECT status, attempts FROM notification_deliveries`).Scan(&status, &attempts)
	if err != nil {
		t.Fatal(err)
	}
	if status != types.DeliveryStatusDelivered || attempts != 1 {
		t.Fatalf("delivery: %s %d", status, attempts)
	}

	// Failing endpoint must not fail Handle and must record a failed row.
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failSrv.Close()
	if _, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "broken", Kind: types.NotificationKindWebhook, URL: failSrv.URL,
	}); err != nil {
		t.Fatal(err)
	}
	if err := svc.Handle(ctx, ev); err != nil {
		t.Fatal(err)
	}
	var failed int
	if err := database.Pool.QueryRow(ctx,
		`SELECT count(*) FROM notification_deliveries WHERE status='failed'`).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Fatalf("expected 1 failed delivery, got %d", failed)
	}

	// Events filter: endpoint subscribed to a different event is skipped.
	filtered, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "filtered", Kind: types.NotificationKindWebhook, URL: srv.URL,
		Events: []string{types.EventInstanceStatus},
	})
	if err != nil {
		t.Fatal(err)
	}
	before := atomic.LoadInt32(&hits)
	if err := svc.Handle(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt32(&hits) != before+1 { // only the unfiltered "hook" endpoint
		t.Fatalf("filtered endpoint should not receive event")
	}
	_ = filtered
}

func TestRetryFailed(t *testing.T) {
	database := itDB(t)
	ctx := context.Background()

	var fail int32 = 1
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.SwapInt32(&fail, 0) == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newService(database, nil, nil)
	ep, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "flaky", Kind: types.NotificationKindWebhook, URL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(types.ApprovalPayload{OrgID: "org:1", ApprovalID: "ap-9", ItemID: "redis"})
	if err := svc.Handle(ctx, &types.OutboxEvent{ID: 2, OrgID: "org:1", EventType: types.EventApprovalRequested, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := database.Pool.QueryRow(ctx,
		`SELECT status FROM notification_deliveries WHERE endpoint_id=$1`, ep.ID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != types.DeliveryStatusFailed {
		t.Fatalf("expected failed, got %s", status)
	}

	retried, err := svc.RetryFailed(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if retried != 1 {
		t.Fatalf("retried %d, want 1", retried)
	}
	var attempts int
	var deliveredAt *string
	if err := database.Pool.QueryRow(ctx,
		`SELECT status, attempts, delivered_at::text FROM notification_deliveries WHERE endpoint_id=$1`,
		ep.ID).Scan(&status, &attempts, &deliveredAt); err != nil {
		t.Fatal(err)
	}
	if status != types.DeliveryStatusDelivered || attempts != 2 || deliveredAt == nil {
		t.Fatalf("after retry: %s attempts=%d deliveredAt=%v", status, attempts, deliveredAt)
	}

	// Nothing left to retry.
	retried, err = svc.RetryFailed(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if retried != 0 {
		t.Fatalf("retried %d, want 0", retried)
	}
}

func TestTestEndpoint(t *testing.T) {
	database := itDB(t)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc := newService(database, nil, nil)
	ctx := context.Background()
	ep, err := svc.CreateEndpoint(ctx, "user-1", "org:1", notifications.EndpointInput{
		Name: "t", Kind: types.NotificationKindSlack, URL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.TestEndpoint(ctx, "user-1", "org:1", ep.ID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != types.DeliveryStatusDelivered || atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("test delivery: %+v hits=%d", d, hits)
	}
	var action string
	if err := database.Pool.QueryRow(ctx,
		`SELECT action FROM audit_events WHERE object_id=$1 AND action='notification_endpoint.tested'`,
		ep.ID).Scan(&action); err != nil {
		t.Fatalf("test audit row: %v", err)
	}
}
