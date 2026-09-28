// Postgres-backed SessionStore for oidc-sso-session extensions (W3 plan
// §5.8): per-user third-party sessions persisted in user_extension_sessions
// with envelope encryption (cryptoenvelope, same KEK/DEK discipline as the
// agent credential vault). Plaintext exists only in function scope; at rest
// the table holds ciphertext only. The seam's provider key (e.g. "argocd")
// is stored in the table's cluster_id column, which the migration defines
// as plain TEXT (no FK) for exactly this kind of provider scoping.
package extensionhost

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/cryptoenvelope"
	"github.com/7K-Inari/inari-server/internal/db"
)

// PgSessionStore implements SessionStore over user_extension_sessions.
type PgSessionStore struct {
	db     *db.DB
	cipher *cryptoenvelope.Cipher
}

// NewPgSessionStore builds the store from a raw KEK (see
// cryptoenvelope.LoadKEK for sourcing). Errors never include key material.
func NewPgSessionStore(database *db.DB, kek []byte) (*PgSessionStore, error) {
	c, err := cryptoenvelope.New(kek)
	if err != nil {
		return nil, err
	}
	return &PgSessionStore{db: database, cipher: c}, nil
}

func (s *PgSessionStore) orgForExtension(ctx context.Context, extensionName string) (string, error) {
	var orgID string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT org_id FROM extensions WHERE name = $1`, extensionName).Scan(&orgID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrSessionNotFound
	}
	if err != nil {
		return "", fmt.Errorf("extensionhost: resolve extension org: %w", err)
	}
	return orgID, nil
}

// Get returns the decrypted session for (user, extension, provider). Missing
// rows fail closed with ErrSessionNotFound; expiry is surfaced via
// UserSession.Expiry and enforced by the caller (ssoSessionProvider).
func (s *PgSessionStore) Get(ctx context.Context, userSub, extensionName, provider string) (*UserSession, error) {
	orgID, err := s.orgForExtension(ctx, extensionName)
	if err != nil {
		return nil, err
	}
	var (
		id       string
		tokenEnc []byte
		dekEnc   []byte
		expires  time.Time
	)
	err = s.db.Pool.QueryRow(ctx,
		`SELECT id, session_token_enc, dek_enc, expires_at
		   FROM user_extension_sessions
		  WHERE org_id = $1 AND user_sub = $2 AND extension = $3 AND cluster_id = $4`,
		orgID, userSub, extensionName, provider).
		Scan(&id, &tokenEnc, &dekEnc, &expires)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("extensionhost: session store get: %w", err)
	}
	raw, err := s.cipher.Decrypt(tokenEnc, dekEnc, sessionAAD(id))
	if err != nil {
		return nil, fmt.Errorf("extensionhost: session decrypt: %w", err)
	}
	cred := string(raw)
	cryptoenvelope.Zero(raw)
	return &UserSession{Provider: provider, Credential: cred, Expiry: expires}, nil
}

// Put stores (replacing any existing row) the session credential encrypted
// under a fresh DEK. The plaintext is zeroed before return.
func (s *PgSessionStore) Put(ctx context.Context, userSub, extensionName string, session *UserSession) error {
	if session == nil || session.Credential == "" {
		return fmt.Errorf("%w: session credential required", ErrInvalidInput)
	}
	orgID, err := s.orgForExtension(ctx, extensionName)
	if err != nil {
		return err
	}
	id := "ues:" + newUUID()
	tokenEnc, dekEnc, err := s.cipher.Encrypt([]byte(session.Credential), sessionAAD(id))
	if err != nil {
		return fmt.Errorf("extensionhost: session encrypt: %w", err)
	}
	expires := session.Expiry
	if expires.IsZero() {
		expires = time.Now().Add(8 * time.Hour)
	}
	// Replace-in-tx so the AAD always matches the surviving row id.
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`DELETE FROM user_extension_sessions
			  WHERE org_id = $1 AND user_sub = $2 AND extension = $3 AND cluster_id = $4`,
			orgID, userSub, extensionName, session.Provider); err != nil {
			return fmt.Errorf("extensionhost: session replace: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO user_extension_sessions
			   (id, org_id, user_sub, extension, cluster_id, session_token_enc, dek_enc, expires_at)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			id, orgID, userSub, extensionName, session.Provider, tokenEnc, dekEnc, expires); err != nil {
			return fmt.Errorf("extensionhost: session put: %w", err)
		}
		return nil
	})
}

// Delete removes the session (logout/revoke); missing rows are not an error.
func (s *PgSessionStore) Delete(ctx context.Context, userSub, extensionName, provider string) error {
	orgID, err := s.orgForExtension(ctx, extensionName)
	if err != nil {
		return err
	}
	if _, err := s.db.Pool.Exec(ctx,
		`DELETE FROM user_extension_sessions
		  WHERE org_id = $1 AND user_sub = $2 AND extension = $3 AND cluster_id = $4`,
		orgID, userSub, extensionName, provider); err != nil {
		return fmt.Errorf("extensionhost: session delete: %w", err)
	}
	return nil
}

func sessionAAD(id string) []byte {
	return []byte("user_extension_sessions:" + id)
}
