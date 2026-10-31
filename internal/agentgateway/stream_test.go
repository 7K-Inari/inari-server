package agentgateway

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

	"github.com/7K-Inari/inari-server/internal/addons"
	"github.com/7K-Inari/inari-server/internal/types"
)

func testSession(checksum string) *session {
	return (&Gateway{}).newSession(&types.Cluster{
		ID: "cluster:test", OrgID: "org:test",
		CapabilityChecksum: checksum,
	})
}

func evWithSeq(typ string, seq int64) *agentv1.Event {
	return &agentv1.Event{EventId: "e1", Type: typ, Sequence: seq}
}

func TestSessionSequenceGapTriggersResyncOnce(t *testing.T) {
	s := testSession("")
	out, err := s.handleEvent(context.Background(), evWithSeq(agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_PONG), 5))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("first event sets baseline, got %d replies", len(out))
	}
	out, err = s.handleEvent(context.Background(), evWithSeq(agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_PONG), 9))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Type != agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_RESYNC_REQUEST) {
		t.Fatalf("gap should emit resync-request, got %+v", out)
	}
	out, err = s.handleEvent(context.Background(), evWithSeq(agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_PONG), 12))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Fatalf("resync must be sent once per session, got %+v", out)
	}
}

func TestSessionHandshakeChecksumDecision(t *testing.T) {
	mkHandshake := func(lastSeen string) *agentv1.Event {
		any, err := anypb.New(&agentv1.HandshakeRequest{
			AgentVersion: "0.1.0", TenantId: "org:test",
			ContractVersion: "inari.agent.v1", LastSeenStateChecksum: lastSeen,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.Event{EventId: "h1", Type: "inari.agent.handshake.v1", Payload: any}
	}

	s := testSession("sum-A")
	out, err := s.handleEvent(context.Background(), mkHandshake("sum-A"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("matching checksum: want 1 reply, got %d", len(out))
	}
	var resp agentv1.HandshakeResponse
	if err := out[0].Payload.UnmarshalTo(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ResyncRequired {
		t.Error("matching checksum must not require resync")
	}

	s = testSession("sum-A")
	out, err = s.handleEvent(context.Background(), mkHandshake("sum-STALE"))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("stale checksum: want handshake response + resync request, got %d", len(out))
	}
	if err := out[0].Payload.UnmarshalTo(&resp); err != nil {
		t.Fatal(err)
	}
	if !resp.ResyncRequired {
		t.Error("stale checksum must require resync")
	}
	if out[1].Type != agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_RESYNC_REQUEST) {
		t.Errorf("second reply = %q, want resync-request", out[1].Type)
	}
}

func TestSessionHandshakeAdvertisesDesiredAgentVersion(t *testing.T) {
	mkHandshake := func() *agentv1.Event {
		any, err := anypb.New(&agentv1.HandshakeRequest{
			AgentVersion: "0.5.0", TenantId: "org:test", ContractVersion: "inari.agent.v1",
		})
		if err != nil {
			t.Fatal(err)
		}
		return &agentv1.Event{EventId: "h1", Type: "inari.agent.handshake.v1", Payload: any}
	}

	s := (&Gateway{cfg: Config{AgentRecommendedVersion: "0.5.1"}}).newSession(&types.Cluster{
		ID: "cluster:test", OrgID: "org:test",
	})
	out, err := s.handleEvent(context.Background(), mkHandshake())
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 reply, got %d", len(out))
	}
	var resp agentv1.HandshakeResponse
	if err := out[0].Payload.UnmarshalTo(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.DesiredAgentVersion != "0.5.1" {
		t.Errorf("DesiredAgentVersion = %q, want 0.5.1", resp.DesiredAgentVersion)
	}

	// No recommendation configured -> empty desired version.
	s = testSession("")
	out, err = s.handleEvent(context.Background(), mkHandshake())
	if err != nil {
		t.Fatal(err)
	}
	if err := out[0].Payload.UnmarshalTo(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.DesiredAgentVersion != "" {
		t.Errorf("DesiredAgentVersion = %q, want empty", resp.DesiredAgentVersion)
	}
}

// reportAddonsSink captures ingested discovery batches.
type reportAddonsSink struct {
	calls []reportAddonsCall
	err   error
}

type reportAddonsCall struct {
	orgID, clusterID string
	items            []addons.DiscoveredAddon
}

func (s *reportAddonsSink) IngestDiscovery(_ context.Context, orgID, clusterID string, items []addons.DiscoveredAddon) error {
	s.calls = append(s.calls, reportAddonsCall{orgID, clusterID, items})
	return s.err
}

// ReportAddons events (Feature C bridge contract) decode the structpb
// payload and reach the discovery sink; malformed payloads drop-and-log.
func TestSessionReportAddonsIngest(t *testing.T) {
	s := testSession("")
	sink := &reportAddonsSink{}
	s.gw.addonDiscovery = sink

	doc, err := structpb.NewStruct(map[string]any{
		"addons": []any{map[string]any{"catalogItem": "platform:cert-manager", "detectedVersion": "v1.16.2"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := anypb.New(doc)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.handleEvent(context.Background(), &agentv1.Event{
		EventId: "e1", Type: addons.ReportAddonsEventType, Payload: payload,
	})
	if err != nil || len(out) != 0 {
		t.Fatalf("report-addons: out=%v err=%v", out, err)
	}
	if len(sink.calls) != 1 || sink.calls[0].clusterID != "cluster:test" || sink.calls[0].orgID != "org:test" {
		t.Fatalf("sink calls: %+v", sink.calls)
	}
	if len(sink.calls[0].items) != 1 || sink.calls[0].items[0].CatalogItem != "platform:cert-manager" {
		t.Errorf("items: %+v", sink.calls[0].items)
	}

	// Malformed payload: drop-and-log, no sink call, no error.
	bad, _ := anypb.New(&agentv1.Ping{})
	if _, err := s.handleEvent(context.Background(), &agentv1.Event{
		EventId: "e2", Type: addons.ReportAddonsEventType, Payload: bad,
	}); err != nil {
		t.Fatalf("malformed payload must be dropped, got %v", err)
	}
	if len(sink.calls) != 1 {
		t.Errorf("malformed payload reached the sink: %+v", sink.calls)
	}

	// Unwired sink: silently ignored.
	s2 := testSession("")
	if _, err := s2.handleEvent(context.Background(), &agentv1.Event{
		EventId: "e3", Type: addons.ReportAddonsEventType, Payload: payload,
	}); err != nil {
		t.Fatalf("unwired sink must not error, got %v", err)
	}
}

func TestSessionUnknownTypeDropped(t *testing.T) {
	s := testSession("")
	out, err := s.handleEvent(context.Background(), &agentv1.Event{EventId: "x", Type: "inari.agent.future-thing.v9"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("unknown event types must be dropped, got %+v", out)
	}
}

type fakeQueue struct {
	rows      map[string]*types.AgentCommand
	completed []string
}

func (q *fakeQueue) Enqueue(context.Context, *types.AgentCommand) error { return nil }
func (q *fakeQueue) Due(context.Context, string, int) ([]types.AgentCommand, error) {
	return nil, nil
}
func (q *fakeQueue) MarkDelivered(context.Context, string) error { return nil }
func (q *fakeQueue) Complete(_ context.Context, id string, _ types.CommandStatus, _ string) error {
	q.completed = append(q.completed, id)
	return nil
}
func (q *fakeQueue) CompletePendingByType(context.Context, string, string, string) error {
	return nil
}
func (q *fakeQueue) Get(_ context.Context, id string) (*types.AgentCommand, error) {
	if c, ok := q.rows[id]; ok {
		return c, nil
	}
	return nil, pgx.ErrNoRows
}

type fakeFailureSink struct{ marked []string }

func (f *fakeFailureSink) MarkFailed(_ context.Context, id, msg string) error {
	f.marked = append(f.marked, id+"|"+msg)
	return nil
}

func ackEvent(t *testing.T, id string, result agentv1.CommandResult) *agentv1.Event {
	t.Helper()
	msg := ""
	if result == agentv1.CommandResult_COMMAND_RESULT_FAILED {
		msg = "boom"
	}
	any, err := anypb.New(&agentv1.CommandAck{CommandId: id, Result: result, Message: msg})
	if err != nil {
		t.Fatal(err)
	}
	typ := agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_COMMAND_ACK)
	if result == agentv1.CommandResult_COMMAND_RESULT_FAILED {
		typ = agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_COMMAND_NACK)
	}
	return &agentv1.Event{EventId: "e1", Type: typ, Payload: any}
}

func TestAckResolvesNamespacedQueueID(t *testing.T) {
	q := &fakeQueue{rows: map[string]*types.AgentCommand{
		"register-argocd-app:web-1": {ID: "register-argocd-app:web-1"},
	}}
	gw := &Gateway{}
	gw.queue = q
	gw.instanceFailures = &fakeFailureSink{}
	s := gw.newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})

	// The agent echoes the bare payload command ID; the queue row is
	// namespaced. The ack must still retire the namespaced row.
	if _, err := s.handleEvent(context.Background(), ackEvent(t, "web-1", agentv1.CommandResult_COMMAND_RESULT_APPLIED)); err != nil {
		t.Fatal(err)
	}
	if len(q.completed) != 1 || q.completed[0] != "register-argocd-app:web-1" {
		t.Fatalf("completed = %v", q.completed)
	}
}

// Addon bridge registrations (Feature C) queue under
// register-argocd-appset:<name> / register-argocd-app-manifest:<name>;
// the agent echoes the bare bridge commandId. Acks must retire them.
func TestAckResolvesBridgeQueueIDs(t *testing.T) {
	q := &fakeQueue{rows: map[string]*types.AgentCommand{
		"register-argocd-appset:inari-addonset-a1":    {ID: "register-argocd-appset:inari-addonset-a1"},
		"register-argocd-app-manifest:inari-addon-b2": {ID: "register-argocd-app-manifest:inari-addon-b2"},
	}}
	gw := &Gateway{}
	gw.queue = q
	gw.instanceFailures = &fakeFailureSink{}
	s := gw.newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})

	if _, err := s.handleEvent(context.Background(), ackEvent(t, "inari-addonset-a1", agentv1.CommandResult_COMMAND_RESULT_APPLIED)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleEvent(context.Background(), ackEvent(t, "inari-addon-b2", agentv1.CommandResult_COMMAND_RESULT_APPLIED)); err != nil {
		t.Fatal(err)
	}
	if len(q.completed) != 2 ||
		q.completed[0] != "register-argocd-appset:inari-addonset-a1" ||
		q.completed[1] != "register-argocd-app-manifest:inari-addon-b2" {
		t.Fatalf("completed = %v", q.completed)
	}
}

func TestNackMarksInstanceFailed(t *testing.T) {
	q := &fakeQueue{rows: map[string]*types.AgentCommand{
		"register-argocd-app:web-1": {ID: "register-argocd-app:web-1"},
	}}
	fs := &fakeFailureSink{}
	gw := &Gateway{}
	gw.queue = q
	gw.instanceFailures = fs
	s := gw.newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})

	if _, err := s.handleEvent(context.Background(), ackEvent(t, "web-1", agentv1.CommandResult_COMMAND_RESULT_FAILED)); err != nil {
		t.Fatal(err)
	}
	if len(fs.marked) != 1 || fs.marked[0] != "web-1|boom" {
		t.Fatalf("marked = %v", fs.marked)
	}
}

func TestAckUnknownIDStillCompletes(t *testing.T) {
	q := &fakeQueue{rows: map[string]*types.AgentCommand{}}
	gw := &Gateway{}
	gw.queue = q
	gw.instanceFailures = &fakeFailureSink{}
	s := gw.newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})
	if _, err := s.handleEvent(context.Background(), ackEvent(t, "ghost", agentv1.CommandResult_COMMAND_RESULT_APPLIED)); err != nil {
		t.Fatal(err)
	}
	if len(q.completed) != 1 || q.completed[0] != "ghost" {
		t.Fatalf("completed = %v", q.completed)
	}
}

// fakeCapsIngestor fakes the capabilityIngestor seam for session tests.
type fakeCapsIngestor struct {
	chunks    [][]types.CapabilityItem
	ingests   []types.CapabilityIngest
	finalized []finalizeCall
}

type finalizeCall struct {
	keep     []types.CapabilityItem
	checksum string
	upserted int
}

func (f *fakeCapsIngestor) Ingest(_ context.Context, _, _ string, upd types.CapabilityIngest) error {
	f.ingests = append(f.ingests, upd)
	return nil
}

func (f *fakeCapsIngestor) IngestChunk(_ context.Context, _, _ string, items []types.CapabilityItem) (int, error) {
	f.chunks = append(f.chunks, items)
	return len(items), nil
}

func (f *fakeCapsIngestor) FinalizeSync(_ context.Context, _, _ string, keep []types.CapabilityItem, stateChecksum string, upserted int) (int, error) {
	f.finalized = append(f.finalized, finalizeCall{keep: keep, checksum: stateChecksum, upserted: upserted})
	return 0, nil
}

func capUpdateEvent(t *testing.T, fullSync bool, checksum string, caps ...*agentv1.Capability) *agentv1.Event {
	t.Helper()
	any, err := anypb.New(&agentv1.CapabilityUpdate{FullSync: fullSync, StateChecksum: checksum, Capabilities: caps})
	if err != nil {
		t.Fatal(err)
	}
	return &agentv1.Event{
		EventId: "ev-cap",
		Type:    agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_CAPABILITY_UPDATE),
		Payload: any,
	}
}

func capCRD(name string) *agentv1.Capability {
	return &agentv1.Capability{
		Kind: agentv1.CapabilityKind_CAPABILITY_KIND_CRD,
		Name: name, Group: "example.com", Version: "v1",
	}
}

func keepNames(items []types.CapabilityItem) map[string]int {
	out := map[string]int{}
	for _, it := range items {
		out[it.Name]++
	}
	return out
}

// Framed full sync: chunks upsert incrementally, but reconciliation
// (delete-missing) and the checksum commit wait for the empty terminal
// chunk — an abandoned replay never deletes live capabilities.
func TestSessionChunkedFullSyncFinalizesOnTerminalChunk(t *testing.T) {
	caps := &fakeCapsIngestor{}
	s := (&Gateway{caps: caps}).newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})
	ctx := context.Background()

	if _, err := s.handleEvent(ctx, capUpdateEvent(t, true, "sum-1", capCRD("a"), capCRD("b"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleEvent(ctx, capUpdateEvent(t, true, "sum-1", capCRD("c"))); err != nil {
		t.Fatal(err)
	}
	if len(caps.chunks) != 2 {
		t.Fatalf("IngestChunk calls = %d, want 2", len(caps.chunks))
	}
	if len(caps.finalized) != 0 {
		t.Fatal("finalize must wait for the terminal chunk")
	}
	if s.cluster.CapabilityChecksum != "" {
		t.Error("checksum must not be committed before the terminal chunk")
	}

	if _, err := s.handleEvent(ctx, capUpdateEvent(t, true, "sum-1")); err != nil {
		t.Fatal(err)
	}
	if len(caps.finalized) != 1 {
		t.Fatalf("finalizes = %d, want 1", len(caps.finalized))
	}
	fin := caps.finalized[0]
	if fin.checksum != "sum-1" || fin.upserted != 3 {
		t.Errorf("finalize = %+v, want checksum sum-1, upserted 3", fin)
	}
	names := keepNames(fin.keep)
	if len(names) != 3 || names["a"] != 1 || names["b"] != 1 || names["c"] != 1 {
		t.Errorf("keep set = %v, want a,b,c", names)
	}
	if s.cluster.CapabilityChecksum != "sum-1" {
		t.Errorf("session checksum = %q, want sum-1 after finalize", s.cluster.CapabilityChecksum)
	}
}

// An incremental upsert landing mid-sync joins the keep set, so finalize
// cannot delete a capability the replay snapshot predates.
func TestSessionIncrementalUpsertDuringSyncJoinsKeepSet(t *testing.T) {
	caps := &fakeCapsIngestor{}
	s := (&Gateway{caps: caps}).newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})
	ctx := context.Background()

	if _, err := s.handleEvent(ctx, capUpdateEvent(t, true, "sum-1", capCRD("a"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleEvent(ctx, capUpdateEvent(t, false, "sum-2", capCRD("c"))); err != nil {
		t.Fatal(err)
	}
	if len(caps.ingests) != 1 {
		t.Fatalf("incremental must go through Ingest, got %d", len(caps.ingests))
	}
	if _, err := s.handleEvent(ctx, capUpdateEvent(t, true, "sum-1")); err != nil {
		t.Fatal(err)
	}
	if len(caps.finalized) != 1 {
		t.Fatalf("finalizes = %d, want 1", len(caps.finalized))
	}
	names := keepNames(caps.finalized[0].keep)
	if names["a"] != 1 || names["c"] != 1 {
		t.Errorf("keep set = %v, want a (chunk) and c (interleaved incremental)", names)
	}
	// The committed checksum is the replay's, not the interleaved
	// incremental's: the next handshake then resyncs once more and
	// converges, instead of trusting state whose deletes never ran.
	if caps.finalized[0].checksum != "sum-1" {
		t.Errorf("finalized checksum = %q, want the replay's sum-1", caps.finalized[0].checksum)
	}
}

// After finalize the accumulator resets: the next sync starts clean.
func TestSessionSyncAccumulatorResetsAfterFinalize(t *testing.T) {
	caps := &fakeCapsIngestor{}
	s := (&Gateway{caps: caps}).newSession(&types.Cluster{ID: "cluster:test", OrgID: "org:test"})
	ctx := context.Background()

	must := func(ev *agentv1.Event) {
		t.Helper()
		if _, err := s.handleEvent(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	must(capUpdateEvent(t, true, "sum-1", capCRD("a")))
	must(capUpdateEvent(t, true, "sum-1")) // terminal
	must(capUpdateEvent(t, true, "sum-2", capCRD("b")))
	must(capUpdateEvent(t, true, "sum-2")) // terminal

	if len(caps.finalized) != 2 {
		t.Fatalf("finalizes = %d, want 2", len(caps.finalized))
	}
	names := keepNames(caps.finalized[1].keep)
	if len(names) != 1 || names["b"] != 1 {
		t.Errorf("second sync keep set = %v, want only b (accumulator must reset)", names)
	}
}
