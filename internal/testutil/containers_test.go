package testutil

import "testing"

func TestSharedPostgresDSN(t *testing.T) {
	s := &SharedPG{adminDSN: "postgres://inari:inari@127.0.0.1:5432/inari?sslmode=disable"}
	got := s.DSN("race_1")
	want := "postgres://inari:inari@127.0.0.1:5432/race_1?sslmode=disable"
	if got != want {
		t.Fatalf("DSN = %q, want %q", got, want)
	}
}

func TestQuoteIdent(t *testing.T) {
	if got := quoteIdent(`it_1`); got != `"it_1"` {
		t.Fatalf("quoteIdent = %q", got)
	}
	if got := quoteIdent(`a"b`); got != `"a""b"` {
		t.Fatalf("quoteIdent escape = %q", got)
	}
}
