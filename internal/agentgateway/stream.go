package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/agent/v1/agentv1connect"
	"github.com/google/uuid"

	"github.com/7K-Inari/inari-server/internal/addons"
	"github.com/7K-Inari/inari-server/internal/fleetmanager"
	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/types"
)

// streamConn abstracts the bidi stream so sessions are testable without a
// network listener. *connect.BidiStream[ConnectRequest, ConnectResponse]
// satisfies it.
type streamConn interface {
	Receive() (*agentv1.ConnectRequest, error)
	Send(*agentv1.ConnectResponse) error
}

// Connect implements inari.agent.v1.EventStreamService: one bidi stream per
// connected agent (plan §5.3 step 2). Duplicate streams for an
// already-connected cluster identity are fenced: the new stream wins and
// the stale session is evicted (closed) deterministically.
func (g *Gateway) Connect(ctx context.Context, stream agentv1connect.EventStreamServiceConnectServerStream) error {
	id := AgentIdentityFromContext(ctx)
	if id == nil {
		return connect.Errorf(connect.CodeUnauthenticated, "unauthenticated")
	}
	cluster, err := g.AuthorizeCluster(ctx, id.ClusterID)
	if err != nil {
		return err
	}
	sctx, cancel := context.WithCancel(ctx)
	h := g.registerSession(cluster.ID, cancel)
	defer func() {
		g.unregisterSession(cluster.ID, h)
		cancel()
	}()
	return g.newSession(cluster).run(sctx, stream)
}

// AuthorizeCluster gates stream admission on the claimed cluster identity: a
// revoked cluster can never reconnect (plan §5.3, §5.10).
func (g *Gateway) AuthorizeCluster(ctx context.Context, clusterID string) (*types.Cluster, error) {
	cluster, err := g.registry.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, connect.Errorf(connect.CodeUnauthenticated, "unknown cluster")
	}
	switch cluster.State {
	case types.ClusterStateActive, types.ClusterStateDegraded:
		return cluster, nil
	case types.ClusterStateRevoked:
		return nil, connect.Errorf(connect.CodePermissionDenied, "cluster is revoked")
	default:
		return nil, connect.Errorf(connect.CodeFailedPrecondition, "cluster not registered")
	}
}

type session struct {
	gw          *Gateway
	cluster     *types.Cluster
	expectedSeq int64
	resyncSent  bool
	pingSeq     int64
	lastBeat    time.Time
	// syncKeep accumulates the membership keys of an in-flight framed full
	// sync (nil when no sync is in flight); syncUpserted counts chunk
	// upserts for the aggregate audit record. Deletes are deferred to the
	// terminal chunk, so a dropped stream never deletes live capabilities.
	syncKeep     map[capabilityKey]struct{}
	syncUpserted int
}

// capabilityKey identifies one capability row for full-sync keep sets.
type capabilityKey struct {
	kind, group, name, version string
}

func (g *Gateway) newSession(c *types.Cluster) *session {
	return &session{gw: g, cluster: c, lastBeat: time.Now()}
}

// handleCapabilityUpdate ingests one capability-update event. Full syncs are
// framed (stream payload sizing fix — CRD-rich snapshots no longer fit one
// stream message): every chunk carries full_sync=true and the sync ends with
// an EMPTY terminal chunk. Chunks upsert immediately; delete-missing
// reconciliation and the checksum commit wait for the terminal chunk.
//
// A full sync without a terminal chunk (a stale pre-chunking agent's
// monolithic sync) upserts but never reconciles and never commits its
// checksum, so the next handshake mismatch resyncs until the agent restarts
// into the chunked image (pre-release, no compat window — parent decision
// D7).
func (s *session) handleCapabilityUpdate(ctx context.Context, upd *agentv1.CapabilityUpdate) error {
	items := mapCapabilityUpdate(upd).Items
	if !upd.FullSync {
		// StateChecksum on an update is the agent's state AFTER applying the
		// delta, so it advances on every change — it must not be compared
		// against the stored checksum here (stale-state detection happens at
		// handshake via LastSeenStateChecksum).
		checksum := upd.StateChecksum
		if s.syncKeep != nil {
			// Mid-sync: the checksum commit is the terminal chunk's job —
			// committing the interleaved incremental's newer checksum would
			// trust state whose deletes never ran. The next handshake
			// mismatch resyncs once more and converges.
			checksum = ""
		}
		if err := s.gw.caps.Ingest(ctx, s.cluster.OrgID, s.cluster.ID, types.CapabilityIngest{
			Items:         items,
			StateChecksum: checksum,
		}); err != nil {
			return fmt.Errorf("ingest capabilities: %w", err)
		}
		if s.syncKeep != nil {
			// An incremental upsert landing mid-sync joins the keep set so
			// finalize cannot delete a capability the replay snapshot
			// predates.
			s.unionKeep(items)
		} else if upd.StateChecksum != "" {
			s.cluster.CapabilityChecksum = upd.StateChecksum
		}
		return nil
	}

	upserted, err := s.gw.caps.IngestChunk(ctx, s.cluster.OrgID, s.cluster.ID, items)
	if err != nil {
		return fmt.Errorf("ingest capability chunk: %w", err)
	}
	if s.syncKeep == nil {
		s.syncKeep = map[capabilityKey]struct{}{}
	}
	s.unionKeep(items)
	s.syncUpserted += upserted
	if len(upd.Capabilities) > 0 {
		return nil // data chunk; reconciliation waits for the terminal chunk
	}

	// Terminal (empty) chunk: reconcile + commit.
	keep := make([]types.CapabilityItem, 0, len(s.syncKeep))
	for k := range s.syncKeep {
		keep = append(keep, types.CapabilityItem{
			Kind: types.CapabilityKind(k.kind), Group: k.group, Name: k.name, Version: k.version,
		})
	}
	if _, err := s.gw.caps.FinalizeSync(ctx, s.cluster.OrgID, s.cluster.ID, keep, upd.StateChecksum, s.syncUpserted); err != nil {
		return fmt.Errorf("finalize capability sync: %w", err)
	}
	s.syncKeep = nil
	s.syncUpserted = 0
	if upd.StateChecksum != "" {
		s.cluster.CapabilityChecksum = upd.StateChecksum
	}
	return nil
}

// unionKeep adds the upserted items' keys to the in-flight sync's keep set.
func (s *session) unionKeep(items []types.CapabilityItem) {
	for _, it := range items {
		if it.Action == types.CapabilityActionDelete {
			continue
		}
		s.syncKeep[capabilityKey{string(it.Kind), it.Group, it.Name, it.Version}] = struct{}{}
	}
}

func newEvent(typ string, payload proto.Message) (*agentv1.Event, error) {
	ev := &agentv1.Event{
		EventId: uuid.NewString(),
		Type:    typ,
		Time:    timestamppb.Now(),
	}
	if payload != nil {
		any, err := anypb.New(payload)
		if err != nil {
			return nil, err
		}
		ev.Payload = any
	}
	return ev, nil
}

func resyncEvent(reason string) *agentv1.Event {
	ev, _ := newEvent(agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_RESYNC_REQUEST),
		&agentv1.ResyncRequest{Reason: reason})
	return ev
}

// handleEvent processes one inbound event and returns events to send back.
func (s *session) handleEvent(ctx context.Context, ev *agentv1.Event) ([]*agentv1.Event, error) {
	var out []*agentv1.Event
	if ev.Sequence > 0 {
		if s.expectedSeq > 0 && ev.Sequence != s.expectedSeq && !s.resyncSent {
			out = append(out, resyncEvent(fmt.Sprintf("sequence gap: expected %d, got %d", s.expectedSeq, ev.Sequence)))
			s.resyncSent = true
		}
		s.expectedSeq = ev.Sequence + 1
	}

	switch agentv1.EventTypeFromString(ev.Type) {
	case agentv1.EventType_EVENT_TYPE_PONG:
		// keepalive reply; last_seen handled below

	case agentv1.EventType_EVENT_TYPE_CAPABILITY_UPDATE:
		var upd agentv1.CapabilityUpdate
		if err := ev.Payload.UnmarshalTo(&upd); err != nil {
			slog.Warn("agentgateway: bad capability-update payload", "cluster", s.cluster.ID, "error", err)
			return out, nil // drop-and-log per compatibility contract
		}
		if err := s.handleCapabilityUpdate(ctx, &upd); err != nil {
			return nil, err
		}

	case agentv1.EventType_EVENT_TYPE_STATUS_UPDATE:
		var upd agentv1.StatusUpdate
		if err := ev.Payload.UnmarshalTo(&upd); err != nil {
			slog.Warn("agentgateway: bad status-update payload", "cluster", s.cluster.ID, "error", err)
			return out, nil
		}
		if s.gw.statusSink != nil {
			if _, err := s.gw.statusSink.ApplyStatus(ctx, s.cluster.OrgID, s.cluster.ID, mapStatusUpdate(&upd)); err != nil {
				return nil, fmt.Errorf("apply status update: %w", err)
			}
		}

	case agentv1.EventType_EVENT_TYPE_COMMAND_ACK, agentv1.EventType_EVENT_TYPE_COMMAND_NACK:
		var ack agentv1.CommandAck
		if err := ev.Payload.UnmarshalTo(&ack); err != nil {
			slog.Warn("agentgateway: bad command ack payload", "cluster", s.cluster.ID, "error", err)
			return out, nil
		}
		status := types.CommandStatusAcked
		if agentv1.EventTypeFromString(ev.Type) == agentv1.EventType_EVENT_TYPE_COMMAND_NACK || ack.Result == agentv1.CommandResult_COMMAND_RESULT_FAILED {
			status = types.CommandStatusNacked
		}
		// The agent echoes the payload's CommandId (bare logical ID), while
		// queue rows are namespaced ("register-argocd-app:<id>", and the
		// Feature C addon bridges "register-argocd-appset:<id>" /
		// "register-argocd-app-manifest:<id>"). Resolve the queued command
		// ID before completing so acks actually retire.
		cmdID := ack.CommandId
		if _, err := s.gw.queue.Get(ctx, cmdID); err != nil {
			for _, prefix := range []string{"register-argocd-app:", "register-argocd-appset:", "register-argocd-app-manifest:"} {
				if _, err := s.gw.queue.Get(ctx, prefix+cmdID); err == nil {
					cmdID = prefix + cmdID
					break
				}
			}
		}
		if err := s.gw.queue.Complete(ctx, cmdID, status, ack.Message); err != nil {
			return nil, fmt.Errorf("complete command: %w", err)
		}
		// A failed register-argocd-app delivery must surface on the instance
		// (state=failed + the agent's message) instead of leaving it stuck in
		// deploying with no error information.
		if status == types.CommandStatusNacked && s.gw.instanceFailures != nil {
			if instanceID, ok := strings.CutPrefix(cmdID, "register-argocd-app:"); ok {
				msg := ack.Message
				if msg == "" {
					msg = "agent failed to register the ArgoCD application"
				}
				if err := s.gw.instanceFailures.MarkFailed(ctx, instanceID, msg); err != nil && !errors.Is(err, inventory.ErrInstanceNotFound) {
					slog.Warn("agentgateway: mark instance failed", "cluster", s.cluster.ID, "instance", instanceID, "error", err)
				}
			}
		}

	case agentv1.EventType_EVENT_TYPE_RESYNC_RESPONSE:
		var resp agentv1.ResyncResponse
		if err := ev.Payload.UnmarshalTo(&resp); err == nil && resp.StateChecksum != "" {
			if err := s.gw.registry.SetCapabilityChecksum(ctx, s.cluster.ID, resp.StateChecksum); err != nil {
				return nil, err
			}
			s.cluster.CapabilityChecksum = resp.StateChecksum
		}
		// Retire any queued resync requests (ops-triggered reconcile, M7.W4):
		// the agent answered with a resync response, not a CommandAck.
		if s.gw.queue != nil {
			if err := s.gw.queue.CompletePendingByType(ctx, s.cluster.ID,
				agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_RESYNC_REQUEST), "resync completed"); err != nil {
				slog.Warn("agentgateway: retire resync commands", "cluster", s.cluster.ID, "error", err)
			}
		}
		s.resyncSent = false

	default:
		// Addon scanner reports (Feature C): the contract bridge payload is
		// a structpb.Struct until inari-api gains the ReportAddons message.
		// Drop-and-log on undecodable payloads (compatibility contract).
		if ev.Type == addons.ReportAddonsEventType {
			if s.gw.addonDiscovery == nil {
				return out, nil
			}
			items, err := addons.DecodeReportAddons(ev.Payload)
			if err != nil {
				slog.Warn("agentgateway: bad report-addons payload", "cluster", s.cluster.ID, "error", err)
				return out, nil
			}
			if err := s.gw.addonDiscovery.IngestDiscovery(ctx, s.cluster.OrgID, s.cluster.ID, items); err != nil {
				return nil, fmt.Errorf("ingest addons: %w", err)
			}
			return out, nil
		}
		// Handshake is carried as a regular event (the contract's stream
		// envelope is ConnectRequest/ConnectResponse only).
		if ev.Payload != nil && ev.Payload.MessageIs(&agentv1.HandshakeRequest{}) {
			var hs agentv1.HandshakeRequest
			if err := ev.Payload.UnmarshalTo(&hs); err != nil {
				return out, nil
			}
			if hs.AgentVersion != "" && s.gw.registry != nil {
				if err := s.gw.registry.SetAgentVersion(ctx, s.cluster.ID, hs.AgentVersion); err != nil {
					slog.Warn("agentgateway: persist agent version", "cluster", s.cluster.ID, "error", err)
				}
				if !fleetmanager.AgentSupported(s.gw.cfg.AgentSupportedRange, s.gw.cfg.CurrentAgentVersion, hs.AgentVersion) {
					slog.Warn("agentgateway: unsupported agent version",
						"cluster", s.cluster.ID, "agent", hs.AgentVersion,
						"supportedRange", s.gw.cfg.AgentSupportedRange,
						"server", s.gw.cfg.CurrentAgentVersion,
						"recommended", s.gw.cfg.AgentRecommendedVersion)
				}
			}
			resync := hs.LastSeenStateChecksum != "" && s.cluster.CapabilityChecksum != "" &&
				hs.LastSeenStateChecksum != s.cluster.CapabilityChecksum
			resp, err := newEvent("inari.agent.handshake.v1", &agentv1.HandshakeResponse{
				SessionId:              uuid.NewString(),
				ServerContractVersions: "inari.agent.v1",
				ResyncRequired:         resync,
				DesiredAgentVersion:    s.gw.cfg.AgentRecommendedVersion,
			})
			if err != nil {
				return nil, err
			}
			out = append(out, resp)
			if resync {
				out = append(out, resyncEvent("handshake checksum mismatch"))
				s.resyncSent = true
			}
		}
		// Unknown types: drop-and-log (compatibility contract).
	}

	// Connection health: throttled heartbeat write.
	if time.Since(s.lastBeat) > 15*time.Second {
		if err := s.gw.registry.RecordHeartbeat(ctx, s.cluster.ID); err != nil {
			slog.Warn("agentgateway: heartbeat", "cluster", s.cluster.ID, "error", err)
		}
		s.lastBeat = time.Now()
	}
	return out, nil
}

// dispatchDue sends pending/unacked commands (at-least-once delivery).
func (s *session) dispatchDue(ctx context.Context, c streamConn) error {
	due, err := s.gw.queue.Due(ctx, s.cluster.ID, 50)
	if err != nil {
		return err
	}
	for _, cmd := range due {
		var any anypb.Any
		if err := protojson.Unmarshal(cmd.Payload, &any); err != nil {
			slog.Warn("agentgateway: bad queued payload", "command", cmd.ID, "error", err)
			continue
		}
		ev := &agentv1.Event{
			EventId:    uuid.NewString(),
			ResourceId: cmd.ID,
			Type:       cmd.Type,
			Payload:    &any,
			Time:       timestamppb.Now(),
		}
		if err := c.Send(&agentv1.ConnectResponse{Event: ev}); err != nil {
			return err
		}
		if err := s.gw.queue.MarkDelivered(ctx, cmd.ID); err != nil {
			return err
		}
	}
	return nil
}

type recvResult struct {
	req *agentv1.ConnectRequest
	err error
}

// run is the session loop: receive events, heartbeat pings, command dispatch.
func (s *session) run(ctx context.Context, c streamConn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	recvCh := make(chan recvResult, 1)
	go func() {
		for {
			req, err := c.Receive()
			select {
			case recvCh <- recvResult{req, err}:
			case <-ctx.Done():
			}
			if err != nil {
				return
			}
		}
	}()

	pingTick := time.NewTicker(s.gw.cfg.PingInterval)
	defer pingTick.Stop()
	cmdTick := time.NewTicker(s.gw.cfg.CommandPollInterval)
	defer cmdTick.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case r := <-recvCh:
			if r.err != nil {
				if errors.Is(r.err, io.EOF) {
					return nil
				}
				return r.err
			}
			if r.req == nil || r.req.Event == nil {
				continue
			}
			out, err := s.handleEvent(ctx, r.req.Event)
			if err != nil {
				return err
			}
			for _, ev := range out {
				if err := c.Send(&agentv1.ConnectResponse{Event: ev}); err != nil {
					return err
				}
			}
		case <-pingTick.C:
			s.pingSeq++
			ev, err := newEvent(agentv1.EventTypeString(agentv1.EventType_EVENT_TYPE_PING),
				&agentv1.Ping{Time: timestamppb.Now(), Sequence: s.pingSeq})
			if err != nil {
				return err
			}
			if err := c.Send(&agentv1.ConnectResponse{Event: ev}); err != nil {
				return err
			}
		case <-cmdTick.C:
			if err := s.dispatchDue(ctx, c); err != nil {
				return err
			}
		}
	}
}
