package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/7K-Inari/inari-api/gen/go/inari/agent/v1"
	"github.com/google/uuid"

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
// connected agent (plan §5.3 step 2).
func (g *Gateway) Connect(ctx context.Context, stream *connect.BidiStream[agentv1.ConnectRequest, agentv1.ConnectResponse]) error {
	id := AgentIdentityFromContext(ctx)
	if id == nil {
		return connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("unauthenticated"))
	}
	cluster, err := g.AuthorizeCluster(ctx, id.ClusterID)
	if err != nil {
		return err
	}
	return g.newSession(cluster).run(ctx, stream)
}

// AuthorizeCluster gates stream admission on the claimed cluster identity: a
// revoked cluster can never reconnect (plan §5.3, §5.10).
func (g *Gateway) AuthorizeCluster(ctx context.Context, clusterID string) (*types.Cluster, error) {
	cluster, err := g.registry.GetCluster(ctx, clusterID)
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("unknown cluster"))
	}
	switch cluster.State {
	case types.ClusterStateActive, types.ClusterStateDegraded:
		return cluster, nil
	case types.ClusterStateRevoked:
		return nil, connect.NewError(connect.CodePermissionDenied, fmt.Errorf("cluster is revoked"))
	default:
		return nil, connect.NewError(connect.CodeFailedPrecondition, fmt.Errorf("cluster not registered"))
	}
}

type session struct {
	gw          *Gateway
	cluster     *types.Cluster
	expectedSeq int64
	resyncSent  bool
	pingSeq     int64
	lastBeat    time.Time
}

func (g *Gateway) newSession(c *types.Cluster) *session {
	return &session{gw: g, cluster: c, lastBeat: time.Now()}
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
		// StateChecksum on an update is the agent's state AFTER applying the
		// delta, so it advances on every change — it must not be compared
		// against the stored checksum here (stale-state detection happens at
		// handshake via LastSeenStateChecksum).
		if err := s.gw.caps.Ingest(ctx, s.cluster.OrgID, s.cluster.ID, mapCapabilityUpdate(&upd)); err != nil {
			return nil, fmt.Errorf("ingest capabilities: %w", err)
		}
		if upd.StateChecksum != "" {
			s.cluster.CapabilityChecksum = upd.StateChecksum
		}

	case agentv1.EventType_EVENT_TYPE_STATUS_UPDATE:
		var upd agentv1.StatusUpdate
		if err := ev.Payload.UnmarshalTo(&upd); err != nil {
			slog.Warn("agentgateway: bad status-update payload", "cluster", s.cluster.ID, "error", err)
			return out, nil
		}
		if s.gw.statusSink != nil {
			if _, err := s.gw.statusSink.ApplyStatus(ctx, s.cluster.ID, mapStatusUpdate(&upd)); err != nil {
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
		if err := s.gw.queue.Complete(ctx, ack.CommandId, status, ack.Message); err != nil {
			return nil, fmt.Errorf("complete command: %w", err)
		}

	case agentv1.EventType_EVENT_TYPE_RESYNC_RESPONSE:
		var resp agentv1.ResyncResponse
		if err := ev.Payload.UnmarshalTo(&resp); err == nil && resp.StateChecksum != "" {
			if err := s.gw.registry.SetCapabilityChecksum(ctx, s.cluster.ID, resp.StateChecksum); err != nil {
				return nil, err
			}
			s.cluster.CapabilityChecksum = resp.StateChecksum
		}
		s.resyncSent = false

	default:
		// Handshake is carried as a regular event (the contract's stream
		// envelope is ConnectRequest/ConnectResponse only).
		if ev.Payload != nil && ev.Payload.MessageIs(&agentv1.HandshakeRequest{}) {
			var hs agentv1.HandshakeRequest
			if err := ev.Payload.UnmarshalTo(&hs); err != nil {
				return out, nil
			}
			resync := hs.LastSeenStateChecksum != "" && s.cluster.CapabilityChecksum != "" &&
				hs.LastSeenStateChecksum != s.cluster.CapabilityChecksum
			resp, err := newEvent("inari.agent.handshake.v1", &agentv1.HandshakeResponse{
				SessionId:              uuid.NewString(),
				ServerContractVersions: "inari.agent.v1",
				ResyncRequired:         resync,
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
