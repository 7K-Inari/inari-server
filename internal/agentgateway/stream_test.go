package agentgateway

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"google.golang.org/protobuf/types/known/anypb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"

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
