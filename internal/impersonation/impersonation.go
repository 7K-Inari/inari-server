// Package impersonation implements control-plane automation acting via
// tenant-scoped virtual users (plan §5.4): automation keeps RBAC uniform by
// acting as a virtual user, and audit records both the real (system) actor
// and the impersonated identity.
//
// v1 is in-process only: no Keycloak token exchange. The virtual user is a
// convention ("user:tenant-<slug>-automation") propagated via context; the
// audit helper stamps AuditEvent.Impersonator from it.
package impersonation

import (
	"context"
	"fmt"
	"strings"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

// VirtualUser returns the tenant-scoped virtual user automation impersonates
// (plan §5.4). orgID may be "org:<id>" or a slug; the prefix is stripped.
func VirtualUser(orgID string) string {
	return "user:tenant-" + strings.TrimPrefix(orgID, "org:") + "-automation"
}

// SystemActor returns the real actor identity for a control-plane module.
func SystemActor(module string) string {
	return "system:" + module
}

type ctxKey struct{}

// WithImpersonator returns a context carrying the impersonated virtual user.
func WithImpersonator(ctx context.Context, virtualUser string) context.Context {
	return context.WithValue(ctx, ctxKey{}, virtualUser)
}

// FromContext extracts the impersonated virtual user, if any.
func FromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxKey{}).(string)
	return v
}

// Stamp fills ev.Impersonator from the context (if not already set) and
// validates that real and impersonated identities differ, so impersonated
// actions are double-audited (plan §5.4).
func Stamp(ctx context.Context, ev *types.AuditEvent) error {
	if ev.Impersonator == "" {
		ev.Impersonator = FromContext(ctx)
	}
	if ev.Impersonator != "" && ev.Impersonator == ev.Actor {
		return fmt.Errorf("impersonation: actor and impersonator must differ")
	}
	return nil
}

// Record appends an audit event after stamping it (see Stamp).
func Record(ctx context.Context, s *audit.Store, q db.Querier, ev *types.AuditEvent) error {
	if err := Stamp(ctx, ev); err != nil {
		return err
	}
	return s.Record(ctx, q, ev)
}
