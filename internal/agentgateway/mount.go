package agentgateway

import (
	"connectrpc.com/connect/v2/connecthttp"
)

// DefaultStreamMaxRecvBytes is the per-message read limit for the
// agent-facing Connect mounts. Capability traffic is byte-bounded at the
// source: the agent chunks CapabilityUpdates to a 2MiB proto-size budget
// (inari-agent internal/capability DefaultMaxBatchBytes), so messages no
// longer scale with cluster CRD count. 8MiB restores the limit's
// backpressure purpose while leaving generous headroom over the chunk
// budget for one oversize member or future growth. (History: the 64MiB
// stopgap from the M5W2 validation admitted monolithic full-sync replays,
// ~10MiB on hub-class clusters; chunking is the systemic fix.)
const DefaultStreamMaxRecvBytes = 8 << 20 // 8MiB

// MountOptions returns the connecthttp transport options for the
// agent-facing RPC mounts (registration, event stream, credentials) —
// applied at connecthttp.Mount in cmd/inari-server. Self-defaulting so the
// raw (pre-withDefaults) Config literal is safe to use at the mount site.
func (c Config) MountOptions() []connecthttp.Option {
	n := c.StreamMaxRecvBytes
	if n <= 0 {
		n = DefaultStreamMaxRecvBytes
	}
	return []connecthttp.Option{connecthttp.WithReadMaxBytes(n)}
}
