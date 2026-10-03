package kubeproxy

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"connectrpc.com/connect"

	"github.com/7K-Inari/inari-server/internal/authn"
)

type stubValidator struct {
	id  *authn.Identity
	err error
}

func (s stubValidator) Validate(context.Context, string) (*authn.Identity, error) {
	return s.id, s.err
}

// fakeStreamConn is the minimal connect.StreamingHandlerConn the
// interceptor touches (RequestHeader only).
type fakeStreamConn struct{ hdr http.Header }

func (fakeStreamConn) Spec() connect.Spec           { return connect.Spec{} }
func (fakeStreamConn) Peer() connect.Peer           { return connect.Peer{} }
func (c fakeStreamConn) RequestHeader() http.Header { return c.hdr }
func (fakeStreamConn) ResponseHeader() http.Header  { return http.Header{} }
func (fakeStreamConn) ResponseTrailer() http.Header { return http.Header{} }
func (fakeStreamConn) Receive(any) error            { return errors.New("not implemented") }
func (fakeStreamConn) Send(any) error               { return errors.New("not implemented") }

func TestAgentAuthInterceptor(t *testing.T) {
	cases := []struct {
		name string
		id   *authn.Identity
		vErr error
		code connect.Code
	}{
		{
			name: "valid tunnel token",
			id:   &authn.Identity{ClusterID: "c1", AuthorizedParty: "tunnel-c1"},
			code: connect.CodeUnknown, // sentinel: expect success
		},
		{
			name: "azp mismatch — another cluster's tunnel client",
			id:   &authn.Identity{ClusterID: "c1", AuthorizedParty: "tunnel-c2"},
			code: connect.CodeUnauthenticated,
		},
		{
			name: "azp mismatch — agent control-plane client",
			id:   &authn.Identity{ClusterID: "c1", AuthorizedParty: "cluster-c1"},
			code: connect.CodeUnauthenticated,
		},
		{
			name: "no cluster_id claim",
			id:   &authn.Identity{AuthorizedParty: "tunnel-c1"},
			code: connect.CodeUnauthenticated,
		},
		{
			name: "validator rejects",
			vErr: errors.New("bad signature"),
			code: connect.CodeUnauthenticated,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			interceptor := AgentAuthInterceptor(stubValidator{id: tc.id, err: tc.vErr})
			conn := fakeStreamConn{hdr: http.Header{"Authorization": []string{"Bearer tok"}}}
			called := false
			err := interceptor.WrapStreamingHandler(func(ctx context.Context, _ connect.StreamingHandlerConn) error {
				called = true
				if AgentIdentityFromContext(ctx) == nil {
					t.Error("handler context lacks agent identity")
				}
				return nil
			})(context.Background(), conn)
			if tc.code == connect.CodeUnknown {
				if err != nil {
					t.Fatalf("err = %v, want success", err)
				}
				if !called {
					t.Fatal("handler not called for valid token")
				}
				return
			}
			if err == nil {
				t.Fatal("expected rejection")
			}
			if got := connect.CodeOf(err); got != tc.code {
				t.Errorf("code = %v, want %v (%v)", got, tc.code, err)
			}
			if called {
				t.Error("handler called for rejected token")
			}
		})
	}

	// Missing header entirely.
	interceptor := AgentAuthInterceptor(stubValidator{id: &authn.Identity{ClusterID: "c1", AuthorizedParty: "tunnel-c1"}})
	err := interceptor.WrapStreamingHandler(func(context.Context, connect.StreamingHandlerConn) error {
		t.Error("handler called without credentials")
		return nil
	})(context.Background(), fakeStreamConn{hdr: http.Header{}})
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no-header code = %v, want unauthenticated", connect.CodeOf(err))
	}
}
