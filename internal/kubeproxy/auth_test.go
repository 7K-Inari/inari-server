package kubeproxy

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectinprocess"

	tunnelv2 "github.com/7K-Inari/inari-api/gen/go/inari/tunnel/v2"

	"github.com/7K-Inari/inari-server/internal/authn"
)

type stubValidator struct {
	id  *authn.Identity
	err error
}

func (s stubValidator) Validate(context.Context, string) (*authn.Identity, error) {
	return s.id, s.err
}

// authPingSpec is a synthetic unary procedure used to exercise the auth
// interceptor end to end through an in-process transport (connect v2 has no
// exported constructor for a server-side CallInfo, so the interceptor cannot
// be invoked directly with headers).
var authPingSpec = connect.Spec{StreamType: connect.StreamTypeUnary, Procedure: "/kubeproxy.test.Auth/Ping"}

func newAuthTestClient(t *testing.T, v authn.Validator) (*connect.Client, *bool) {
	t.Helper()
	called := new(bool)
	server := connect.NewServer(AgentAuthInterceptor(v))
	server.Register(connect.Method{
		Spec: authPingSpec,
		Handler: func(ctx context.Context, _ connect.Spec, stream connect.ServerStream) error {
			*called = true
			if AgentIdentityFromContext(ctx) == nil {
				t.Error("handler context lacks agent identity")
			}
			var req tunnelv2.TunnelPing
			if err := stream.Receive(&req); err != nil {
				return err
			}
			return stream.Send(&req)
		},
	})
	return connect.NewClient(connectinprocess.New(server)), called
}

func callAuthPing(ctx context.Context, client *connect.Client, authHeader string) error {
	ctx, info := connect.NewClientContext(ctx)
	if authHeader != "" {
		info.RequestHeader().Set("Authorization", authHeader)
	}
	return client.CallUnary(ctx, authPingSpec, &tunnelv2.TunnelPing{}, &tunnelv2.TunnelPing{})
}

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
			client, called := newAuthTestClient(t, stubValidator{id: tc.id, err: tc.vErr})
			err := callAuthPing(context.Background(), client, "Bearer tok")
			if tc.code == connect.CodeUnknown {
				if err != nil {
					t.Fatalf("err = %v, want success", err)
				}
				if !*called {
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
			if *called {
				t.Error("handler called for rejected token")
			}
		})
	}
}

func TestAgentAuthInterceptorNoHeader(t *testing.T) {
	server := connect.NewServer(AgentAuthInterceptor(stubValidator{
		id: &authn.Identity{ClusterID: "c1", AuthorizedParty: "tunnel-c1"},
	}))
	server.Register(connect.Method{
		Spec: authPingSpec,
		Handler: func(context.Context, connect.Spec, connect.ServerStream) error {
			t.Error("handler called without credentials")
			return nil
		},
	})
	client := connect.NewClient(connectinprocess.New(server))
	err := callAuthPing(context.Background(), client, "")
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no-header code = %v, want unauthenticated", connect.CodeOf(err))
	}
}
