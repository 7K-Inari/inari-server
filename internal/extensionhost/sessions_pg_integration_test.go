//go:build integration

package extensionhost_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/extensionhost"
)

func seedSessionStore(t *testing.T) (*extensionhost.PgSessionStore, *db.DB) {
	t.Helper()
	database := itDB(t)
	seedOrg(t, database, "org:1")
	svc := extensionhost.NewService(database, extensionhost.NewStore(), audit.NewStore())
	if _, _, err := svc.Register(context.Background(), "user-1", extensionhost.RegisterInput{
		OrgID: "org:1", Name: "argocd", Version: "0.1.0", Endpoint: "http://127.0.0.1:9001",
	}); err != nil {
		t.Fatal(err)
	}
	kek := make([]byte, 32)
	if _, err := rand.Read(kek); err != nil {
		t.Fatal(err)
	}
	store, err := extensionhost.NewPgSessionStore(database, kek)
	if err != nil {
		t.Fatal(err)
	}
	return store, database
}

func TestPgSessionStoreRoundTrip(t *testing.T) {
	store, _ := seedSessionStore(t)
	ctx := context.Background()
	exp := time.Now().Add(2 * time.Hour).Truncate(time.Millisecond)

	if _, err := store.Get(ctx, "user-1", "argocd", "argocd"); !errors.Is(err, extensionhost.ErrSessionNotFound) {
		t.Fatalf("get before put = %v, want ErrSessionNotFound", err)
	}
	if err := store.Put(ctx, "user-1", "argocd", &extensionhost.UserSession{
		Provider: "argocd", Credential: "secret-session-token", Expiry: exp,
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, "user-1", "argocd", "argocd")
	if err != nil {
		t.Fatal(err)
	}
	if got.Credential != "secret-session-token" || got.Provider != "argocd" {
		t.Fatalf("credential mismatch: %+v", got)
	}
	if got.Expiry.Before(time.Now()) {
		t.Fatalf("expiry not preserved: %v", got.Expiry)
	}

	// Replace: second Put overwrites, no duplicate-key error.
	if err := store.Put(ctx, "user-1", "argocd", &extensionhost.UserSession{
		Provider: "argocd", Credential: "rotated-token", Expiry: exp,
	}); err != nil {
		t.Fatal(err)
	}
	got, err = store.Get(ctx, "user-1", "argocd", "argocd")
	if err != nil || got.Credential != "rotated-token" {
		t.Fatalf("after replace: %+v, %v", got, err)
	}

	// Isolation: different user and different provider see nothing.
	if _, err := store.Get(ctx, "user-2", "argocd", "argocd"); !errors.Is(err, extensionhost.ErrSessionNotFound) {
		t.Fatalf("cross-user read = %v, want ErrSessionNotFound", err)
	}
	if _, err := store.Get(ctx, "user-1", "argocd", "gitlab"); !errors.Is(err, extensionhost.ErrSessionNotFound) {
		t.Fatalf("cross-provider read = %v, want ErrSessionNotFound", err)
	}

	if err := store.Delete(ctx, "user-1", "argocd", "argocd"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, "user-1", "argocd", "argocd"); !errors.Is(err, extensionhost.ErrSessionNotFound) {
		t.Fatalf("get after delete = %v, want ErrSessionNotFound", err)
	}
}

func TestPgSessionStoreCiphertextOnlyAtRest(t *testing.T) {
	store, database := seedSessionStore(t)
	ctx := context.Background()
	const secret = "plaintext-must-never-appear"
	if err := store.Put(ctx, "user-1", "argocd", &extensionhost.UserSession{
		Provider: "argocd", Credential: secret, Expiry: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := database.Pool.Query(ctx,
		`SELECT session_token_enc::text, dek_enc::text FROM user_extension_sessions`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b string
		if err := rows.Scan(&a, &b); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(a, secret) || strings.Contains(b, secret) {
			t.Fatal("plaintext session material found at rest")
		}
	}
}
