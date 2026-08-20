// Sidecar handshake + supervision (plan §5.8): plugins are verified via the
// inari-plugin-sdk handshake (magic cookie env for subprocess mode, protocol
// version + identity via PluginContractService.GetInfo, optional artifact
// checksum). Crash isolation: a dead sidecar never affects the control
// plane — the proxy fails closed with 502 and the supervisor restarts the
// process with backoff.
package extensionhost

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"connectrpc.com/connect"

	pluginv1 "github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1"
	"github.com/7K-Inari/inari-api/gen/go/inari/plugin/v1/pluginv1connect"

	"github.com/7K-Inari/inari-server/internal/types"
)

// MagicCookieKey/MagicCookieValue implement the go-plugin-style handshake:
// the control plane only proxies to processes it launched with this cookie,
// and SDK-based plugins refuse to serve without it.
const (
	MagicCookieKey   = "INARI_PLUGIN_MAGIC_COOKIE"
	MagicCookieValue = "inari-plugin-v1"
)

// handshakeTimeout bounds the GetInfo verification call.
const handshakeTimeout = 5 * time.Second

// VerifyHandshake dials the sidecar endpoint and checks the plugin contract:
// protocol version must be supported and the reported name/version must match
// the registry record (defense against a rogue process squatting on the
// endpoint).
func VerifyHandshake(ctx context.Context, endpoint string, ext *types.Extension) (*pluginv1.PluginInfo, error) {
	client := pluginv1connect.NewPluginContractServiceClient(http.DefaultClient, endpoint)
	hctx, cancel := context.WithTimeout(ctx, handshakeTimeout)
	defer cancel()
	resp, err := client.GetInfo(hctx, connect.NewRequest(&pluginv1.GetInfoRequest{}))
	if err != nil {
		return nil, fmt.Errorf("extensionhost: handshake getinfo: %w", err)
	}
	info := resp.Msg.GetInfo()
	if info == nil {
		return nil, fmt.Errorf("extensionhost: handshake: empty plugin info")
	}
	if info.GetApiVersion() != SupportedProtocolVersion {
		return nil, fmt.Errorf("%w: got %q want %q", ErrProtocolVersion, info.GetApiVersion(), SupportedProtocolVersion)
	}
	if info.GetName() != ext.Name || info.GetVersion() != ext.Version {
		return nil, fmt.Errorf("%w: plugin reports %s@%s, registry has %s@%s",
			ErrPluginIdentity, info.GetName(), info.GetVersion(), ext.Name, ext.Version)
	}
	return info, nil
}

// ProcessSupervisor launches and watches plugin subprocesses (exec mode).
// Each plugin runs in its own OS process — a crash is isolated to that
// process and the supervisor restarts it with capped exponential backoff.
type ProcessSupervisor struct {
	mu      sync.Mutex
	procs   map[string]*supervisedProc
	backoff time.Duration
	maxBack time.Duration
	// stateCallback reports readiness transitions to the registry (optional).
	stateCallback func(ctx context.Context, extensionID, state string)
}

type supervisedProc struct {
	extensionID string
	command     []string
	endpoint    string
	cancel      context.CancelFunc
}

func NewProcessSupervisor() *ProcessSupervisor {
	return &ProcessSupervisor{
		procs:   map[string]*supervisedProc{},
		backoff: 100 * time.Millisecond,
		maxBack: 30 * time.Second,
	}
}

// WithStateCallback wires registry state updates (ready/degraded) from the
// supervision loop.
func (s *ProcessSupervisor) WithStateCallback(cb func(ctx context.Context, extensionID, state string)) *ProcessSupervisor {
	s.stateCallback = cb
	return s
}

// Supervise starts (and keeps alive) the plugin subprocess for ext until the
// returned stop function is called. The command runs with the magic-cookie
// env the SDK requires.
func (s *ProcessSupervisor) Supervise(ctx context.Context, ext *types.Extension, command []string) (stop func(), err error) {
	if len(command) == 0 {
		return nil, fmt.Errorf("%w: command is required for exec mode", ErrInvalidInput)
	}
	if err := VerifyChecksum(command[0], ext.Checksum); err != nil {
		return nil, err
	}
	pctx, cancel := context.WithCancel(context.Background())
	p := &supervisedProc{extensionID: ext.ID, command: command, endpoint: ext.Endpoint, cancel: cancel}
	s.mu.Lock()
	s.procs[ext.ID] = p
	s.mu.Unlock()
	go s.run(pctx, p)
	return func() {
		cancel()
		s.mu.Lock()
		delete(s.procs, ext.ID)
		s.mu.Unlock()
	}, nil
}

func (s *ProcessSupervisor) run(ctx context.Context, p *supervisedProc) {
	backoff := s.backoff
	for {
		cmd := exec.CommandContext(ctx, p.command[0], p.command[1:]...) //nolint:gosec // plugin path is operator-configured
		cmd.Env = append(os.Environ(), MagicCookieKey+"="+MagicCookieValue)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			s.report(ctx, p.extensionID, types.ExtensionStateDegraded)
			if !sleepOrDone(ctx, backoff) {
				return
			}
			backoff = min(backoff*2, s.maxBack)
			continue
		}
		err := cmd.Wait()
		if ctx.Err() != nil {
			return // supervised stop
		}
		s.report(ctx, p.extensionID, types.ExtensionStateDegraded)
		_ = err // crash isolation: log-and-restart, never propagate
		if !sleepOrDone(ctx, backoff) {
			return
		}
		backoff = min(backoff*2, s.maxBack)
	}
}

func (s *ProcessSupervisor) report(ctx context.Context, extensionID, state string) {
	if s.stateCallback != nil {
		s.stateCallback(ctx, extensionID, state)
	}
}

// Stop terminates all supervised processes.
func (s *ProcessSupervisor) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.procs {
		p.cancel()
	}
	s.procs = map[string]*supervisedProc{}
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
