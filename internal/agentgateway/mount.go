package agentgateway

import (
	"connectrpc.com/connect/v2/connecthttp"
)

// DefaultStreamMaxRecvBytes is the per-message read limit for the
// agent-facing Connect mounts. connect's default (4MiB) is too small for
// capability full-sync replays from CRD-rich clusters: the agent's CRD
// capability collector embeds openAPIV3 schemas, and a hub carrying
// Crossplane + provider-keycloak + ESO + CNPG + ArgoCD CRDs exceeds 4MiB
// easily (~10MiB observed in e2e). Sessions then die on every full sync
// (resource_exhausted), taking status streaming down with them.
const DefaultStreamMaxRecvBytes = 64 << 20 // 64MiB

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
