package clusterregistry

import (
	"strings"
	"testing"
)

func TestHashTokenDeterministic(t *testing.T) {
	h1 := HashToken("abc")
	h2 := HashToken("abc")
	if h1 != h2 {
		t.Errorf("HashToken not deterministic: %q vs %q", h1, h2)
	}
	if h1 == "abc" {
		t.Error("HashToken returned plaintext")
	}
	if len(h1) != 64 {
		t.Errorf("HashToken length = %d, want 64 (sha256 hex)", len(h1))
	}
}

func TestRandomTokenGenerator(t *testing.T) {
	g := randomTokenGenerator{}
	t1, err := g.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	t2, err := g.NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if t1 == t2 {
		t.Error("two tokens identical")
	}
	if len(t1) < 40 {
		t.Errorf("token too short: %d", len(t1))
	}
	if strings.ContainsAny(t1, "+/=") {
		t.Errorf("token not base64url: %q", t1)
	}
}

func TestNewUUID(t *testing.T) {
	a, b := newUUID(), newUUID()
	if a == b {
		t.Error("duplicate uuids")
	}
	if len(a) != 36 || a[14] != '4' {
		t.Errorf("not a v4 uuid: %q", a)
	}
}
