//go:build integration

package agentgateway

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/capabilities"
	"github.com/7K-Inari/inari-server/internal/clusterregistry"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

type fakeClients struct {
	created  []string
	disabled []string
}

func (f *fakeClients) CreateClusterClient(_ context.Context, clusterID string) (string, error) {
	f.created = append(f.created, clusterID)
	return "cluster-" + clusterID, nil
}
func (f *fakeClients) DisableClient(_ context.Context, clientID string) error {
	f.disabled = append(f.disabled, clientID)
	return nil
}

func setupDB(t *testing.T) *db.DB {
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
	return database
}

func seedOrg(t *testing.T, database *db.DB, id string) {
	t.Helper()
	_, err := database.Pool.Exec(context.Background(),
		`INSERT INTO organizations (id, slug, display_name, keycloak_org_id) VALUES ($1,$2,$3,$4)`,
		id, "acme", "Acme", "kc-"+id)
	if err != nil {
		t.Fatal(err)
	}
}

type rig struct {
	gw       *Gateway
	registry *clusterregistry.Service
	caps     *capabilities.Service
	clients  *fakeClients
	db       *db.DB
}

func newRig(t *testing.T, approvalRequired bool) *rig {
	t.Helper()
	database := setupDB(t)
	seedOrg(t, database, "org:1")
	clients := &fakeClients{}
	auditStore := audit.NewStore()
	registry := clusterregistry.NewService(database, clients, clusterregistry.NewStore(), auditStore,
		time.Hour, approvalRequired)
	caps := capabilities.NewService(database, capabilities.NewStore(), auditStore)
	gw := NewGateway(database, registry, clients, caps, auditStore, Config{
		OIDCIssuerURL:  "http://keycloak/realms/inari",
		ESOSecretStore: "inari-platform",
	})
	return &rig{gw: gw, registry: registry, caps: caps, clients: clients, db: database}
}

func registerReq(token string) *connect.Request[agentv1.RegisterClusterRequest] {
	return connect.NewRequest(&agentv1.RegisterClusterRequest{
		RegistrationToken: token,
		AgentVersion:      "0.1.0",
		ContractVersion:   "inari.agent.v1",
		ClusterLabels:     map[string]string{"env": "dev"},
		KubernetesVersion: "v1.31.0",
	})
}

func TestRegistrationExchangeEndToEnd(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()

	cluster, err := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", map[string]string{"env": "dev"})
	if err != nil {
		t.Fatalf("CreateCluster: %v", err)
	}
	if cluster.State != types.ClusterStatePendingRegistration {
		t.Errorf("state = %q, want pending_registration", cluster.State)
	}

	token, _, err := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}

	res, err := r.gw.RegisterCluster(ctx, registerReq(token))
	if err != nil {
		t.Fatalf("RegisterCluster: %v", err)
	}
	if res.Msg.ClientId != "cluster-"+cluster.ID {
		t.Errorf("client_id = %q", res.Msg.ClientId)
	}
	if res.Msg.ClientSecretDelivery.GetEsoSecretStore() != "inari-platform" {
		t.Errorf("eso store = %q", res.Msg.ClientSecretDelivery.GetEsoSecretStore())
	}
	if len(r.clients.created) != 1 {
		t.Errorf("keycloak clients created = %v", r.clients.created)
	}

	got, err := r.registry.GetCluster(ctx, cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != types.ClusterStateActive {
		t.Errorf("state = %q, want active", got.State)
	}
	if got.KubernetesVersion != "v1.31.0" {
		t.Errorf("k8s version = %q", got.KubernetesVersion)
	}

	// Token reuse is rejected (one-time).
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err == nil {
		t.Fatal("token reuse accepted")
	} else if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("reuse code = %v, want FailedPrecondition (%v)", connect.CodeOf(err), err)
	}

	// Unknown token is rejected.
	if _, err := r.gw.RegisterCluster(ctx, registerReq("bogus")); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("bogus token code = %v, want Unauthenticated", connect.CodeOf(err))
	}
}

func TestEnrollmentApprovalRequired(t *testing.T) {
	r := newRig(t, true)
	ctx := context.Background()

	cluster, err := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	if err != nil {
		t.Fatal(err)
	}
	if cluster.State != types.ClusterStatePendingApproval {
		t.Fatalf("state = %q, want pending_approval", cluster.State)
	}
	token, _, err := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("unapproved registration code = %v, want FailedPrecondition", connect.CodeOf(err))
	}
	if _, err := r.registry.ApproveCluster(ctx, "admin-1", cluster.ID); err != nil {
		t.Fatalf("ApproveCluster: %v", err)
	}
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatalf("registration after approval: %v", err)
	}
}

func capabilityEvent(t *testing.T, fullSync bool, checksum string, caps ...*agentv1.Capability) *agentv1.Event {
	t.Helper()
	any, err := anypb.New(&agentv1.CapabilityUpdate{FullSync: fullSync, StateChecksum: checksum, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.Event{
		EventId: "ev-1",
		Type:    agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_CAPABILITY_UPDATE),
		Payload: any,
	}
}

func TestCapabilityIngestPersists(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}

	sess := r.gw.newSession(mustCluster(t, r, cluster.ID))

	_, err := sess.handleEvent(ctx, capabilityEvent(t, true, "sum-1",
		&agentv1.Capability{Kind: agentv1.CapabilityKind_CAPABILITY_KIND_CRD, Name: "foos.example.com", Group: "example.com", Version: "v1"},
		&agentv1.Capability{Kind: agentv1.CapabilityKind_CAPABILITY_KIND_KRO_RGD, Name: "web-service", Version: "v0.2.0"},
	))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	list, err := r.caps.List(ctx, cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("capabilities = %d, want 2", len(list))
	}

	// Incremental delete removes one record.
	_, err = sess.handleEvent(ctx, capabilityEvent(t, false, "sum-2",
		&agentv1.Capability{Kind: agentv1.CapabilityKind_CAPABILITY_KIND_CRD, Name: "foos.example.com", Group: "example.com", Version: "v1", Action: agentv1.CapabilityAction_CAPABILITY_ACTION_DELETE},
	))
	if err != nil {
		t.Fatal(err)
	}
	list, err = r.caps.List(ctx, cluster.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].Name != "web-service" {
		t.Fatalf("after delete: %+v", list)
	}

	// Checksum is tracked on the cluster for resync decisions.
	got, _ := r.registry.GetCluster(ctx, cluster.ID)
	if got.CapabilityChecksum != "sum-2" {
		t.Errorf("checksum = %q, want sum-2", got.CapabilityChecksum)
	}

	// Audit trail exists.
	events, err := audit.NewStore().List(ctx, r.db.Pool, "org:1", 20)
	if err != nil {
		t.Fatal(err)
	}
	var sawIngest bool
	for _, ev := range events {
		if ev.Action == "capabilities.ingested" {
			sawIngest = true
		}
	}
	if !sawIngest {
		t.Error("no capabilities.ingested audit event")
	}
}

// fakeConn implements the session stream seam for dispatch tests.
type fakeConn struct {
	sent []*agentv1.ConnectResponse
}

func (f *fakeConn) Receive() (*agentv1.ConnectRequest, error) { return nil, io.EOF }
func (f *fakeConn) Send(r *agentv1.ConnectResponse) error {
	f.sent = append(f.sent, r)
	return nil
}

func TestCommandDispatchAtLeastOnce(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}

	any, err := anypb.New(&agentv1.ApplyBundle{CommandId: "cmd-1", Source: &agentv1.ApplyBundle_OciRef{OciRef: "oci://x/bundle:v1"}})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.gw.Queue().Enqueue(ctx, &types.AgentCommand{
		ID: "cmd-1", ClusterID: cluster.ID,
		Type:    agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_APPLY_BUNDLE),
		Payload: raw,
	}); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	conn := &fakeConn{}
	sess := r.gw.newSession(mustCluster(t, r, cluster.ID))
	if err := sess.dispatchDue(ctx, conn); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if len(conn.sent) != 1 {
		t.Fatalf("sent = %d, want 1", len(conn.sent))
	}
	if conn.sent[0].Event.Type != agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_APPLY_BUNDLE) {
		t.Errorf("dispatched type = %q", conn.sent[0].Event.Type)
	}

	// Unacked command is redelivered after the retry window.
	r.gw.queue.retryAfter = 0
	if err := sess.dispatchDue(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if len(conn.sent) != 2 {
		t.Fatalf("redelivery: sent = %d, want 2", len(conn.sent))
	}

	// Ack completes the command; no further delivery.
	ackAny, _ := anypb.New(&agentv1.CommandAck{CommandId: "cmd-1", Result: agentv1.CommandResult_COMMAND_RESULT_APPLIED})
	if _, err := sess.handleEvent(ctx, &agentv1.Event{
		EventId: "ack-1",
		Type:    agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_COMMAND_ACK),
		Payload: ackAny,
	}); err != nil {
		t.Fatal(err)
	}
	if err := sess.dispatchDue(ctx, conn); err != nil {
		t.Fatal(err)
	}
	if len(conn.sent) != 2 {
		t.Errorf("acked command redelivered: sent = %d", len(conn.sent))
	}
}

func TestRevokedClusterCannotReconnect(t *testing.T) {
	r := newRig(t, false)
	ctx := context.Background()
	cluster, _ := r.registry.CreateCluster(ctx, "user-1", "org:1", "kind-dev", nil)
	token, _, _ := r.registry.IssueToken(ctx, "user-1", cluster.ID)
	if _, err := r.gw.RegisterCluster(ctx, registerReq(token)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.gw.AuthorizeCluster(ctx, cluster.ID); err != nil {
		t.Fatalf("active cluster must connect: %v", err)
	}

	if err := r.registry.RevokeCluster(ctx, "admin-1", cluster.ID); err != nil {
		t.Fatalf("RevokeCluster: %v", err)
	}
	if len(r.clients.disabled) != 1 {
		t.Errorf("keycloak client not disabled: %v", r.clients.disabled)
	}
	if _, err := r.gw.AuthorizeCluster(ctx, cluster.ID); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Errorf("revoked reconnect code = %v, want PermissionDenied", connect.CodeOf(err))
	}

	// Regression guard: error is a typed connect error, not nil.
	if _, err := r.gw.AuthorizeCluster(ctx, cluster.ID); err == nil || errors.Is(err, io.EOF) {
		t.Error("revoked cluster unexpectedly admitted")
	}
}

func mustCluster(t *testing.T, r *rig, id string) *types.Cluster {
	t.Helper()
	c, err := r.registry.GetCluster(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
