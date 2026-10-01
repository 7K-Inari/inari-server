//go:build integration

package audit_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats-server/v2/server"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/eventbus"
	"github.com/7K-Inari/inari-server/internal/eventbus/eventbustest"
	"github.com/7K-Inari/inari-server/internal/testutil"
	"github.com/7K-Inari/inari-server/internal/testutil/testdb"
	"github.com/7K-Inari/inari-server/internal/types"
)

func itDB(t *testing.T) *db.DB {
	t.Helper()
	ctx := context.Background()
	pg, err := testutil.SharedPostgres(ctx)
	if err != nil {
		t.Skipf("testcontainers unavailable: %v", err)
	}
	database, err := testdb.NewDatabase(t, pg)
	if err != nil {
		t.Fatal(err)
	}
	return database
}

func appendEvent(t *testing.T, ctx context.Context, database *db.DB, orgID, eventType string, payload any) int64 {
	t.Helper()
	if err := database.WithTx(ctx, func(tx pgx.Tx) error {
		return audit.AppendOutbox(ctx, tx, orgID, eventType, payload)
	}); err != nil {
		t.Fatalf("append outbox: %v", err)
	}
	var id int64
	if err := database.Pool.QueryRow(ctx, `SELECT max(id) FROM outbox`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

type outboxRow struct {
	published bool
	attempts  int
	lastError string
}

func readRow(t *testing.T, ctx context.Context, database *db.DB, id int64) outboxRow {
	t.Helper()
	var r outboxRow
	err := database.Pool.QueryRow(ctx,
		`SELECT published_at IS NOT NULL, attempts, last_error FROM outbox WHERE id = $1`, id).
		Scan(&r.published, &r.attempts, &r.lastError)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// recorder is an outbox handler capturing every delivered event.
type recorder struct {
	mu     sync.Mutex
	events []types.OutboxEvent
	calls  int
	fn     func(ctx context.Context, ev *types.OutboxEvent) error
}

func (r *recorder) handler(types_ ...string) audit.NamedHandler {
	return audit.Named("recorder", audit.HandlerFunc{
		Types: types_,
		Fn: func(ctx context.Context, ev *types.OutboxEvent) error {
			r.mu.Lock()
			r.calls++
			r.events = append(r.events, *ev)
			fn := r.fn
			r.mu.Unlock()
			if fn != nil {
				return fn(ctx, ev)
			}
			return nil
		},
	})
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls
}

func (r *recorder) distinctIDs() map[int64]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := map[int64]bool{}
	for _, ev := range r.events {
		ids[ev.ID] = true
	}
	return ids
}

func newDispatcher(t *testing.T, database *db.DB, bus *eventbus.Bus, h audit.NamedHandler, opts ...audit.DispatcherOption) *audit.Dispatcher {
	t.Helper()
	d, err := audit.NewDispatcher(context.Background(), database, bus, 10*time.Millisecond, []audit.NamedHandler{h}, opts...)
	if err != nil {
		t.Fatalf("new dispatcher: %v", err)
	}
	return d
}

func TestRelayPublishesUnpublishedRows(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)
	rec := &recorder{}
	d := newDispatcher(t, database, bus, rec.handler("tenant.created", "team.created"))

	id1 := appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})
	id2 := appendEvent(t, ctx, database, "org:1", "team.created", map[string]string{"slug": "acme", "team": "platform"})

	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []int64{id1, id2} {
		if r := readRow(t, ctx, database, id); !r.published {
			t.Errorf("row %d not marked published", id)
		}
	}

	n, err := d.DeliverOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("DeliverOnce delivered %d, want 2", n)
	}
	ids := rec.distinctIDs()
	if !ids[id1] || !ids[id2] {
		t.Errorf("handler received %v, want rows %d and %d", ids, id1, id2)
	}
	rec.mu.Lock()
	ev := rec.events[0]
	rec.mu.Unlock()
	if ev.OrgID != "org:1" || ev.EventType != "tenant.created" || ev.OccurredAt.IsZero() {
		t.Errorf("event fields lost in round trip: %+v", ev)
	}
}

func TestRelayDedupByOutboxID(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)
	rec := &recorder{}
	d := newDispatcher(t, database, bus, rec.handler("tenant.created"))

	id := appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate a crash after PubAck but before commit: the same row is
	// relayed again with the same Nats-Msg-Id and the dedup window must
	// collapse it.
	if _, err := database.Pool.Exec(ctx, `UPDATE outbox SET published_at = NULL WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := bus.JetStream().Stream(ctx, eventbus.StreamNameOutbox)
	if err != nil {
		t.Fatal(err)
	}
	info, err := s.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs != 1 {
		t.Errorf("stream holds %d messages, want 1 (dedup by outbox ID)", info.State.Msgs)
	}
}

func TestRelayPublishFailureFailOpen(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	natsServer := eventbustest.Server(t)
	bus, err := eventbus.Connect(ctx, natsServer.ClientURL(), eventbus.WithConnectBudget(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureOutboxStream(ctx, 1); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	d := newDispatcher(t, database, bus, rec.handler("tenant.created"), audit.WithPublishAckBudget(300*time.Millisecond))

	id := appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})
	// NATS outage: rows must stay unpublished (fail-open) with the failure
	// recorded, never a crash and never a lost event.
	natsServer.Shutdown()
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r := readRow(t, ctx, database, id)
	if r.published {
		t.Error("row marked published despite NATS outage")
	}
	if r.attempts != 1 || r.lastError == "" {
		t.Errorf("row = %+v, want attempts=1 and last_error set", r)
	}

	// Budget exhaustion dead-letters the unpublishable row.
	if _, err := database.Pool.Exec(ctx, `UPDATE outbox SET attempts = $1 WHERE id = $2`, audit.DefaultMaxPublishAttempts-1, id); err != nil {
		t.Fatal(err)
	}
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	r = readRow(t, ctx, database, id)
	if !r.published || r.lastError == "" {
		t.Errorf("dead-lettered row = %+v, want published with last_error", r)
	}
}

func TestRelayDrainsAfterNATSRestart(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)

	// Fixed-port embedded server so the outage can be restarted on the same
	// address; JetStream state survives via the shared store dir.
	storeDir := t.TempDir()
	start := func(t *testing.T, port int) *server.Server {
		t.Helper()
		s, err := server.NewServer(&server.Options{
			JetStream: true,
			StoreDir:  storeDir,
			Host:      "127.0.0.1",
			Port:      port,
		})
		if err != nil {
			t.Fatalf("nats-server: %v", err)
		}
		go s.Start()
		if !s.ReadyForConnections(5 * time.Second) {
			t.Fatal("nats-server did not become ready")
		}
		return s
	}
	natsServer := start(t, -1)
	port := natsServer.Addr().(*net.TCPAddr).Port

	bus, err := eventbus.Connect(ctx, natsServer.ClientURL(), eventbus.WithConnectBudget(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer bus.Close()
	if err := bus.EnsureOutboxStream(ctx, 1); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{}
	d := newDispatcher(t, database, bus, rec.handler("tenant.created"), audit.WithPublishAckBudget(300*time.Millisecond))

	id := appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})

	// Outage: the row accumulates unpublished (fail-open).
	natsServer.Shutdown()
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if r := readRow(t, ctx, database, id); r.published {
		t.Fatal("row marked published despite NATS outage")
	}

	// Recovery: the client auto-reconnects and the next relay publishes the
	// accumulated row; the handler then receives it exactly once.
	natsServer = start(t, port)
	defer natsServer.Shutdown()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if err := d.RelayOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if r := readRow(t, ctx, database, id); r.published {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("row never drained after NATS recovery")
		}
		time.Sleep(500 * time.Millisecond)
	}
	if _, err := d.DeliverOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if got := rec.distinctIDs(); len(got) != 1 || !got[id] {
		t.Errorf("handler received %v, want exactly row %d", got, id)
	}
}

func TestTwoDispatchersShareDeliveries(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)
	recA := &recorder{}
	recB := &recorder{}
	hA := audit.Named("shared", audit.HandlerFunc{Types: []string{"tenant.created"}, Fn: func(_ context.Context, ev *types.OutboxEvent) error {
		recA.mu.Lock()
		recA.events = append(recA.events, *ev)
		recA.mu.Unlock()
		return nil
	}})
	hB := audit.Named("shared", audit.HandlerFunc{Types: []string{"tenant.created"}, Fn: func(_ context.Context, ev *types.OutboxEvent) error {
		recB.mu.Lock()
		recB.events = append(recB.events, *ev)
		recB.mu.Unlock()
		return nil
	}})
	dA := newDispatcher(t, database, bus, hA)
	dB := newDispatcher(t, database, bus, hB)

	want := map[int64]bool{}
	for range 10 {
		want[appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})] = true
	}
	if err := dA.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Both dispatchers join the same durable consumer group: deliveries
	// load-balance between them with no duplicates.
	ctxRun, cancel := context.WithCancel(ctx)
	defer cancel()
	go dB.Run(ctxRun)
	deadline := time.Now().Add(15 * time.Second)
	for {
		_, _ = dA.DeliverOnce(ctx)
		merged := recA.distinctIDs()
		for id := range recB.distinctIDs() {
			merged[id] = true
		}
		if len(merged) >= len(want) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d of %d distinct events (A=%d B=%d)", len(merged), len(want), len(recA.distinctIDs()), len(recB.distinctIDs()))
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	total := len(recA.distinctIDs()) + len(recB.distinctIDs())
	if total != len(want) {
		t.Errorf("total deliveries = %d, want exactly %d (no duplicates across replicas)", total, len(want))
	}
}

func TestHandlerErrorRedelivers(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)
	rec := &recorder{}
	fail := true
	rec.fn = func(context.Context, *types.OutboxEvent) error {
		if fail {
			fail = false
			return errors.New("transient failure")
		}
		return nil
	}
	d := newDispatcher(t, database, bus, rec.handler("tenant.created"))

	appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := d.DeliverOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 1 {
		t.Fatalf("calls = %d, want 1 (first attempt fails)", rec.count())
	}
	// First backoff step is 1s.
	time.Sleep(1200 * time.Millisecond)
	if _, err := d.DeliverOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if rec.count() != 2 {
		t.Errorf("calls = %d, want 2 (redelivery succeeded)", rec.count())
	}
}

func TestPoisonHandlerDeadLetters(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)
	rec := &recorder{}
	rec.fn = func(context.Context, *types.OutboxEvent) error { return errors.New("always fails") }
	d := newDispatcher(t, database, bus, rec.handler("tenant.created"), audit.WithMaxDeliver(3))

	id := appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})
	if err := d.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}
	// Deliveries 1..3 with the 1s/2s backoff steps in between; the third is
	// terminal.
	for i, wait := range []time.Duration{0, 1200 * time.Millisecond, 2200 * time.Millisecond} {
		time.Sleep(wait)
		if _, err := d.DeliverOnce(ctx); err != nil {
			t.Fatal(err)
		}
		if rec.count() != i+1 {
			t.Fatalf("after delivery %d: calls = %d", i+1, rec.count())
		}
	}
	r := readRow(t, ctx, database, id)
	if !r.published {
		t.Error("row lost published mark")
	}
	if r.lastError == "" {
		t.Error("terminal dead-letter did not write last_error back to the row")
	}
	if n, err := d.DeliverOnce(ctx); err != nil || n != 0 {
		t.Errorf("post-dead-letter DeliverOnce = %d, %v; want 0, nil", n, err)
	}
}

func TestDeliverAllBacklogOnLateConsumer(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)

	// Publish before any consumer exists (e.g. first boot, or a renamed
	// handler's fresh durable): DeliverAll must still deliver the backlog.
	pub := audit.NewNATSPublisher(bus)
	ev := &types.OutboxEvent{ID: 4242, OrgID: "org:1", EventType: "tenant.created",
		Payload: []byte(`{"slug":"acme"}`), OccurredAt: time.Now()}
	if err := pub.Publish(ctx, ev); err != nil {
		t.Fatal(err)
	}

	rec := &recorder{}
	d := newDispatcher(t, database, bus, rec.handler("tenant.created"))
	n, err := d.DeliverOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || !rec.distinctIDs()[4242] {
		t.Errorf("DeliverOnce = %d, ids %v; want backlog event 4242", n, rec.distinctIDs())
	}
}

func TestGracefulShutdownNaksInFlight(t *testing.T) {
	ctx := context.Background()
	database := itDB(t)
	bus := eventbustest.Bus(t)

	started := make(chan struct{})
	unblock := make(chan struct{})
	h1 := audit.Named("shared", audit.HandlerFunc{Types: []string{"tenant.created"}, Fn: func(ctx context.Context, _ *types.OutboxEvent) error {
		close(started)
		<-unblock
		return ctx.Err() // handlers observe cancellation
	}})
	rec := &recorder{}
	h2 := audit.Named("shared", audit.HandlerFunc{Types: []string{"tenant.created"}, Fn: func(_ context.Context, ev *types.OutboxEvent) error {
		rec.mu.Lock()
		rec.events = append(rec.events, *ev)
		rec.mu.Unlock()
		return nil
	}})
	d1 := newDispatcher(t, database, bus, h1, audit.WithConsumerAckWait(2*time.Second))
	d2 := newDispatcher(t, database, bus, h2, audit.WithConsumerAckWait(2*time.Second))

	appendEvent(t, ctx, database, "org:1", "tenant.created", map[string]string{"slug": "acme"})
	if err := d1.RelayOnce(ctx); err != nil {
		t.Fatal(err)
	}

	ctx1, cancel1 := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { d1.Run(ctx1); close(done) }()
	<-started
	cancel1()
	close(unblock)
	<-done

	// The in-flight message was Nak'd on shutdown, but its first redelivery
	// can still land in the dead dispatcher's open pull request; that copy
	// is bounded by the (test-shortened) ack wait, after which the surviving
	// dispatcher picks the event up.
	deadline := time.Now().Add(15 * time.Second)
	for {
		n, err := d2.DeliverOnce(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			cons, _ := bus.JetStream().Consumer(ctx, eventbus.StreamNameOutbox, "outbox-shared")
			ci, _ := cons.Info(ctx)
			t.Fatalf("surviving dispatcher never got the Nak'd message (pending=%d ackPending=%d redelivered=%d)",
				ci.NumPending, ci.NumAckPending, ci.NumRedelivered)
		}
	}
	if len(rec.distinctIDs()) != 1 {
		t.Errorf("surviving dispatcher handler got %d events, want 1", len(rec.distinctIDs()))
	}
}
