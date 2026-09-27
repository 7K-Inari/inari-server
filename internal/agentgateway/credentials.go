// W3 credential vault (plan §5.8): short-lived per-user tokens handed to
// in-cluster agents without persisting plaintext. The extension hop delivers
// the raw token in memory (InvokeAction metadata); the vault stores only
// envelope-encrypted ciphertext (per-row DEK wrapped by the platform KEK,
// AAD-bound to the credential ref), with a TTL equal to the command timeout.
// Redemption is bound to the cluster identity from the agent's token claim,
// single-use (hard delete on redeem), and expired rows are swept. Token
// material is never logged and never appears in errors.
package agentgateway

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/7K-Inari/inari-server/internal/cryptoenvelope"
	"github.com/7K-Inari/inari-server/internal/db"
)

var (
	// ErrCredentialNotFound: no live row for the ref (unknown or already
	// redeemed and hard-deleted).
	ErrCredentialNotFound = errors.New("agentgateway: credential not found")
	// ErrCredentialExpired: the ref exists but its TTL has elapsed.
	ErrCredentialExpired = errors.New("agentgateway: credential expired")
	// ErrCredentialRedeemed: the ref was already redeemed (reserved for
	// mark-then-sweep deployments; hard delete makes it unreachable today).
	ErrCredentialRedeemed = errors.New("agentgateway: credential already redeemed")
	// ErrCredentialClusterMismatch: the ref is bound to a different cluster
	// than the agent's token claim.
	ErrCredentialClusterMismatch = errors.New("agentgateway: credential bound to a different cluster")
)

// CredentialVault is the Postgres-backed envelope-encrypted store behind
// AgentCredentials.RedeemUserCredential.
type CredentialVault struct {
	db  *db.DB
	enc *cryptoenvelope.Cipher
	// now overrides the clock in tests; nil means time.Now.
	now func() time.Time
}

// NewCredentialVault builds the vault from a 32-byte KEK (see
// cryptoenvelope.LoadKEK).
func NewCredentialVault(d *db.DB, kek []byte) (*CredentialVault, error) {
	enc, err := cryptoenvelope.New(kek)
	if err != nil {
		return nil, err
	}
	return &CredentialVault{db: d, enc: enc}, nil
}

func (v *CredentialVault) clock() time.Time {
	if v.now != nil {
		return v.now()
	}
	return time.Now()
}

func credentialAAD(ref string) []byte {
	return []byte("agent_command_credentials:" + ref)
}

// DBTX is satisfied by *pgxpool.Pool and pgx.Tx.
type DBTX interface {
	Exec(ctx context.Context, sql string, arguments ...any) (pgconn.CommandTag, error)
}

// Mint encrypts token and stores it bound to (clusterID, commandID) with the
// given TTL (the command timeout). The returned ref passes the hop
// validator; the caller's token buffer is wiped before return.
func (v *CredentialVault) Mint(ctx context.Context, clusterID, commandID string, token []byte, ttl time.Duration) (string, error) {
	ref := v.NewRef()
	return ref, v.MintWithRefTx(ctx, v.db.Pool, ref, clusterID, commandID, token, ttl)
}

// NewRef generates a credential ref (passes the hop validator).
func (v *CredentialVault) NewRef() string { return "cred:" + uuid.NewString() }

// MintWithRefTx encrypts token under ref and stores it bound to
// (clusterID, commandID) with the given TTL (the command timeout), inside a
// caller-owned transaction/connection so the credential and its
// agent_commands row commit atomically (command_id FK requires the command
// row first). The caller's token buffer is wiped before return.
func (v *CredentialVault) MintWithRefTx(ctx context.Context, tx DBTX, ref, clusterID, commandID string, token []byte, ttl time.Duration) error {
	defer cryptoenvelope.Zero(token)
	if len(token) == 0 {
		return errors.New("agentgateway: empty token")
	}
	if ttl <= 0 {
		return errors.New("agentgateway: credential TTL must be positive")
	}
	tokenEnc, dekEnc, err := v.enc.Encrypt(token, credentialAAD(ref))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO agent_command_credentials
		    (credential_ref, command_id, cluster_id, token_enc, dek_enc, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		ref, commandID, clusterID, tokenEnc, dekEnc, v.clock().Add(ttl))
	if err != nil {
		return fmt.Errorf("agentgateway: mint credential: %w", err)
	}
	return nil
}

// Redeem returns the plaintext token for ref, enforcing cluster binding and
// single use: on success the row is hard-deleted in the same transaction.
// Fail closed: unknown, expired, or cross-cluster refs are typed errors and
// never leak token material.
func (v *CredentialVault) Redeem(ctx context.Context, ref, clusterID string) (token []byte, expiresAt time.Time, err error) {
	tx, err := v.db.Pool.Begin(ctx)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("agentgateway: redeem: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var boundCluster string
	var tokenEnc, dekEnc []byte
	var redeemedAt *time.Time
	err = tx.QueryRow(ctx, `
		SELECT cluster_id, token_enc, dek_enc, expires_at, redeemed_at
		FROM agent_command_credentials
		WHERE credential_ref = $1
		FOR UPDATE`, ref).
		Scan(&boundCluster, &tokenEnc, &dekEnc, &expiresAt, &redeemedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, time.Time{}, ErrCredentialNotFound
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("agentgateway: redeem: %w", err)
	}
	if redeemedAt != nil {
		return nil, time.Time{}, ErrCredentialRedeemed
	}
	if boundCluster != clusterID {
		return nil, time.Time{}, ErrCredentialClusterMismatch
	}
	if !v.clock().Before(expiresAt) {
		return nil, time.Time{}, ErrCredentialExpired
	}
	// Decrypt before the hard delete: a decrypt failure (corrupt row, KEK
	// rotation) must not destroy a credential the agent could otherwise
	// redeem after the underlying key issue is fixed.
	token, err = v.enc.Decrypt(tokenEnc, dekEnc, credentialAAD(ref))
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("agentgateway: redeem decrypt: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM agent_command_credentials WHERE credential_ref = $1`, ref); err != nil {
		return nil, time.Time{}, fmt.Errorf("agentgateway: redeem delete: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, time.Time{}, fmt.Errorf("agentgateway: redeem commit: %w", err)
	}
	return token, expiresAt, nil
}

// Sweep hard-deletes expired rows; returns the number removed.
func (v *CredentialVault) Sweep(ctx context.Context) (int, error) {
	tag, err := v.db.Pool.Exec(ctx, `
		DELETE FROM agent_command_credentials WHERE expires_at < now()`)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			return 0, fmt.Errorf("agentgateway: sweep: %s", pgErr.Message)
		}
		return 0, fmt.Errorf("agentgateway: sweep: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// RunSweepLoop sweeps expired credentials on the interval until ctx is done
// (run under leaderlease so only one replica sweeps).
func (v *CredentialVault) RunSweepLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Best-effort: rows that survive a failed sweep are retried on
			// the next tick and can never be redeemed past expiry anyway.
			_, _ = v.Sweep(ctx)
		}
	}
}
