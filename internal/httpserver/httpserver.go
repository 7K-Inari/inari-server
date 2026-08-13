// Package httpserver wires chi + huma, global middleware, and health probes.
package httpserver

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/7K-Inari/inari-server/internal/authn"
)

// ReadinessChecker reports whether a dependency is ready.
type ReadinessChecker interface {
	Ping(ctx context.Context) error
}

func NewRouter(log *slog.Logger, v authn.Validator, ready ReadinessChecker) (chi.Router, huma.API) {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.Recoverer)
	r.Use(requestLogger(log))

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	r.Get("/readyz", func(w http.ResponseWriter, req *http.Request) {
		if err := ready.Ping(req.Context()); err != nil {
			http.Error(w, `{"status":"unavailable"}`, http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ready"}`))
	})

	api := humachi.New(r, huma.DefaultConfig("inari-server", "0.1.0"))
	if api.OpenAPI().Components.SecuritySchemes == nil {
		api.OpenAPI().Components.SecuritySchemes = map[string]*huma.SecurityScheme{}
	}
	api.OpenAPI().Components.SecuritySchemes["bearer"] = &huma.SecurityScheme{
		Type: "http", Scheme: "bearer", BearerFormat: "JWT",
	}
	api.UseMiddleware(authMiddleware(v))
	return r, api
}

// authMiddleware validates the bearer token for every huma operation and
// stores the Identity in context. Health probes bypass it (plain chi routes).
func authMiddleware(v authn.Validator) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if !requiresAuth(ctx.Operation()) {
			next(ctx)
			return
		}
		raw := ctx.Header("Authorization")
		const prefix = "Bearer "
		if len(raw) <= len(prefix) || !strings.EqualFold(raw[:len(prefix)], prefix) {
			writeError(ctx, http.StatusUnauthorized, "missing or malformed authorization header")
			return
		}
		id, err := v.Validate(ctx.Context(), raw[len(prefix):])
		if err != nil {
			writeError(ctx, http.StatusUnauthorized, "invalid token")
			return
		}
		next(huma.WithValue(ctx, identityKey{}, id))
	}
}

func requiresAuth(op *huma.Operation) bool {
	for _, sec := range op.Security {
		if _, ok := sec["bearer"]; ok {
			return true
		}
	}
	return false
}

func writeError(ctx huma.Context, status int, msg string) {
	ctx.SetStatus(status)
	ctx.SetHeader("Content-Type", "application/json")
	_, _ = ctx.BodyWriter().Write([]byte(`{"detail":"` + msg + `"}`))
}

type identityKey struct{}

// IdentityFromHuma extracts the authenticated identity from a huma context.
func IdentityFromHuma(ctx huma.Context) *authn.Identity {
	id, _ := ctx.Context().Value(identityKey{}).(*authn.Identity)
	return id
}

// IdentityFromContext extracts the authenticated identity from a std context.
func IdentityFromContext(ctx context.Context) *authn.Identity {
	id, _ := ctx.Value(identityKey{}).(*authn.Identity)
	return id
}

func requestLogger(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration_ms", time.Since(start).Milliseconds(),
				"request_id", chimw.GetReqID(r.Context()),
			)
		})
	}
}

// SecurityRequirement returns the huma security spec for bearer-authed ops.
func SecurityRequirement() []map[string][]string {
	return []map[string][]string{{"bearer": {}}}
}
