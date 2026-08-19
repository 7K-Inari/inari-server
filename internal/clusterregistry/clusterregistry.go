// Package clusterregistry implements the Cluster Registry module (plan
// §5.2): cluster records (identity, reported k8s version/labels, connection
// health — never a kubeconfig), one-time TTL'd registration tokens, optional
// enrollment approval, and revocation via the Keycloak client.
package clusterregistry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrClusterNotFound   = errors.New("cluster not found")
	ErrClusterNameTaken  = errors.New("cluster name already exists in tenant")
	ErrTokenInvalid      = errors.New("registration token invalid")
	ErrTokenExpired      = errors.New("registration token expired")
	ErrTokenUsed         = errors.New("registration token already used")
	ErrClusterNotPending = errors.New("cluster is not pending approval")
	ErrClusterRevoked    = errors.New("cluster is revoked")
)

// ClientManager provisions per-cluster OIDC identity (plan §5.3). Only
// client metadata crosses this seam — never secrets.
type ClientManager interface {
	// CreateClusterClient creates the cluster-<id> client (client-credentials
	// grant, hardcoded cluster_id claim) and returns its clientID.
	CreateClusterClient(ctx context.Context, clusterID string) (clientID string, err error)
	// DisableClient revokes a cluster's identity (plan §5.3 revocation path).
	DisableClient(ctx context.Context, clientID string) error
}

// TokenGenerator issues the plaintext bootstrap token (seam for tests).
type TokenGenerator interface {
	NewToken() (plaintext string, err error)
}

type randomTokenGenerator struct{}

// NewToken returns a 256-bit base64url token. Only its SHA-256 hash is stored.
func (randomTokenGenerator) NewToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("clusterregistry: token rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken derives the stored form of a plaintext token.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// Store is the PostgreSQL projection of cluster registry state.
type Store struct{}

func NewStore() *Store { return &Store{} }

const clusterCols = `id, org_id, name, kubernetes_version, distribution, oidc_issuer_url, labels, keycloak_client_id, state,
	capability_checksum, connected_at, last_seen_at, created_at`

func scanCluster(row interface{ Scan(...any) error }) (*types.Cluster, error) {
	var c types.Cluster
	var labels []byte
	err := row.Scan(&c.ID, &c.OrgID, &c.Name, &c.KubernetesVersion, &c.Distribution, &c.OIDCIssuerURL, &labels, &c.KeycloakClientID,
		&c.State, &c.CapabilityChecksum, &c.ConnectedAt, &c.LastSeenAt, &c.CreatedAt)
	if err != nil {
		return nil, err
	}
	if len(labels) > 0 {
		if err := json.Unmarshal(labels, &c.Labels); err != nil {
			return nil, fmt.Errorf("clusterregistry: labels: %w", err)
		}
	}
	return &c, nil
}

func (s *Store) CreateCluster(ctx context.Context, q db.Querier, c *types.Cluster) error {
	labels, err := json.Marshal(c.Labels)
	if err != nil {
		return err
	}
	const sql = `INSERT INTO clusters (id, org_id, name, labels, state) VALUES ($1,$2,$3,$4,$5)
	             RETURNING ` + clusterCols
	row := q.QueryRow(ctx, sql, c.ID, c.OrgID, c.Name, labels, c.State)
	out, err := scanCluster(row)
	if isUniqueViolation(err) {
		return ErrClusterNameTaken
	}
	if err != nil {
		return err
	}
	*c = *out
	return nil
}

func (s *Store) GetCluster(ctx context.Context, q db.Querier, id string) (*types.Cluster, error) {
	const sql = `SELECT ` + clusterCols + ` FROM clusters WHERE id = $1`
	c, err := scanCluster(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrClusterNotFound
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Store) ListClusters(ctx context.Context, q db.Querier, orgID string) ([]types.Cluster, error) {
	const sql = `SELECT ` + clusterCols + ` FROM clusters WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.Cluster
	for rows.Next() {
		c, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

func (s *Store) SetState(ctx context.Context, q db.Querier, id string, state types.ClusterState) error {
	const sql = `UPDATE clusters SET state = $2 WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClusterNotFound
	}
	return nil
}

func (s *Store) MarkRegistered(ctx context.Context, q db.Querier, id, clientID, k8sVersion string, labels map[string]string) error {
	raw, err := json.Marshal(labels)
	if err != nil {
		return err
	}
	const sql = `UPDATE clusters SET keycloak_client_id = $2, kubernetes_version = $3, labels = $4,
	             state = 'active', connected_at = now(), last_seen_at = now() WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, clientID, k8sVersion, raw)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClusterNotFound
	}
	return nil
}

// SetMetadata records agent-reported cluster metadata (k8s distribution and
// OIDC issuer URL) used for IRSA-vs-web-identity decisions (plan §5.7).
func (s *Store) SetMetadata(ctx context.Context, q db.Querier, id, distribution, oidcIssuerURL string) error {
	const sql = `UPDATE clusters SET distribution = $2, oidc_issuer_url = $3 WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, distribution, oidcIssuerURL)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrClusterNotFound
	}
	return nil
}

func (s *Store) TouchLastSeen(ctx context.Context, q db.Querier, id string) error {	const sql = `UPDATE clusters SET last_seen_at = now() WHERE id = $1`
	_, err := q.Exec(ctx, sql, id)
	return err
}

func (s *Store) SetCapabilityChecksum(ctx context.Context, q db.Querier, id, checksum string) error {
	const sql = `UPDATE clusters SET capability_checksum = $2 WHERE id = $1`
	_, err := q.Exec(ctx, sql, id, checksum)
	return err
}

func (s *Store) InsertToken(ctx context.Context, q db.Querier, t *types.RegistrationToken, tokenHash string) error {
	const sql = `INSERT INTO registration_tokens (cluster_id, token_hash, expires_at, created_by)
	             VALUES ($1,$2,$3,$4) RETURNING id, created_at`
	return q.QueryRow(ctx, sql, t.ClusterID, tokenHash, t.ExpiresAt, t.CreatedBy).
		Scan(&t.ID, &t.CreatedAt)
}

// ConsumeToken atomically validates and burns a token: it must exist, be
// unused, and be unexpired. The row is locked FOR UPDATE inside the caller's
// TX so replay races lose.
func (s *Store) ConsumeToken(ctx context.Context, q db.Querier, tokenHash string, now time.Time) (*types.RegistrationToken, error) {
	const sel = `SELECT id, cluster_id, expires_at, used_at, created_by, created_at
	             FROM registration_tokens WHERE token_hash = $1 FOR UPDATE`
	var t types.RegistrationToken
	err := q.QueryRow(ctx, sel, tokenHash).
		Scan(&t.ID, &t.ClusterID, &t.ExpiresAt, &t.UsedAt, &t.CreatedBy, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTokenInvalid
	}
	if err != nil {
		return nil, err
	}
	if t.UsedAt != nil {
		return nil, ErrTokenUsed
	}
	if now.After(t.ExpiresAt) {
		return nil, ErrTokenExpired
	}
	const upd = `UPDATE registration_tokens SET used_at = now() WHERE id = $1`
	if _, err := q.Exec(ctx, upd, t.ID); err != nil {
		return nil, err
	}
	return &t, nil
}

// Service orchestrates cluster lifecycle: DB projection + audit + outbox in
// one TX, Keycloak identity via ClientManager.
type Service struct {
	db               *db.DB
	clients          ClientManager
	tokens           TokenGenerator
	store            *Store
	audit            *audit.Store
	tokenTTL         time.Duration
	approvalRequired bool
	now              func() time.Time
}

func NewService(d *db.DB, clients ClientManager, store *Store, auditStore *audit.Store, tokenTTL time.Duration, approvalRequired bool) *Service {
	if tokenTTL <= 0 {
		tokenTTL = time.Hour
	}
	return &Service{
		db:               d,
		clients:          clients,
		tokens:           randomTokenGenerator{},
		store:            store,
		audit:            auditStore,
		tokenTTL:         tokenTTL,
		approvalRequired: approvalRequired,
		now:              time.Now,
	}
}

// CreateCluster registers a new cluster record. With enrollment approval
// enabled the record starts pending_approval (double opt-in, plan §10) and
// tokens can only be consumed after ApproveCluster.
func (s *Service) CreateCluster(ctx context.Context, actor, orgID, name string, labels map[string]string) (*types.Cluster, error) {
	state := types.ClusterStatePendingRegistration
	if s.approvalRequired {
		state = types.ClusterStatePendingApproval
	}
	c := &types.Cluster{
		ID:     "cluster:" + newUUID(),
		OrgID:  orgID,
		Name:   name,
		Labels: labels,
		State:  state,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateCluster(ctx, tx, c); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cluster.created", ObjectType: "cluster", ObjectID: c.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventClusterCreated, types.ClusterPayload{
			OrgID: orgID, ClusterID: c.ID, Name: name,
		})
	})
	if err != nil {
		return nil, err
	}
	return c, nil
}

func (s *Service) ListClusters(ctx context.Context, orgID string) ([]types.Cluster, error) {
	return s.store.ListClusters(ctx, s.db.Pool, orgID)
}

func (s *Service) GetCluster(ctx context.Context, id string) (*types.Cluster, error) {
	return s.store.GetCluster(ctx, s.db.Pool, id)
}

// IssueToken mints a one-time TTL'd registration token; the plaintext is
// returned once and only its hash is persisted.
func (s *Service) IssueToken(ctx context.Context, actor, clusterID string) (plaintext string, _ *types.RegistrationToken, err error) {
	c, err := s.store.GetCluster(ctx, s.db.Pool, clusterID)
	if err != nil {
		return "", nil, err
	}
	if c.State == types.ClusterStateRevoked {
		return "", nil, ErrClusterRevoked
	}
	plaintext, err = s.tokens.NewToken()
	if err != nil {
		return "", nil, err
	}
	t := &types.RegistrationToken{
		ClusterID: clusterID,
		ExpiresAt: s.now().Add(s.tokenTTL),
		CreatedBy: actor,
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.InsertToken(ctx, tx, t, HashToken(plaintext)); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: c.OrgID, Actor: actor, Action: "registration-token.issued", ObjectType: "cluster", ObjectID: clusterID,
			Payload: json.RawMessage(fmt.Sprintf(`{"tokenId":%q,"expiresAt":%q}`, t.ID, t.ExpiresAt.Format(time.RFC3339))),
		})
	})
	if err != nil {
		return "", nil, err
	}
	return plaintext, t, nil
}

// ApproveCluster completes the double opt-in: pending_approval →
// pending_registration so a token can be consumed.
func (s *Service) ApproveCluster(ctx context.Context, actor, clusterID string) (*types.Cluster, error) {
	c, err := s.store.GetCluster(ctx, s.db.Pool, clusterID)
	if err != nil {
		return nil, err
	}
	if c.State != types.ClusterStatePendingApproval {
		return nil, ErrClusterNotPending
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetState(ctx, tx, clusterID, types.ClusterStatePendingRegistration); err != nil {
			return err
		}
		return s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: c.OrgID, Actor: actor, Action: "cluster.approved", ObjectType: "cluster", ObjectID: clusterID,
		})
	})
	if err != nil {
		return nil, err
	}
	c.State = types.ClusterStatePendingRegistration
	return c, nil
}

// RevokeCluster disables the Keycloak client and flips state to revoked;
// the agent can never reconnect (plan §5.3, §5.11).
func (s *Service) RevokeCluster(ctx context.Context, actor, clusterID string) error {
	c, err := s.store.GetCluster(ctx, s.db.Pool, clusterID)
	if err != nil {
		return err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetState(ctx, tx, clusterID, types.ClusterStateRevoked); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: c.OrgID, Actor: actor, Action: "cluster.revoked", ObjectType: "cluster", ObjectID: clusterID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, c.OrgID, types.EventClusterRevoked, types.ClusterPayload{
			OrgID: c.OrgID, ClusterID: clusterID,
		})
	})
	if err != nil {
		return err
	}
	if c.KeycloakClientID != "" {
		if err := s.clients.DisableClient(ctx, c.KeycloakClientID); err != nil {
			return fmt.Errorf("clusterregistry: disable client: %w", err)
		}
	}
	return nil
}

// ConsumeRegistrationToken validates and burns a bootstrap token, returning
// the cluster it was issued for. Used by the registration exchange only.
// Revoked or still-pending-approval clusters are rejected inside the TX so
// the token is NOT burned — the exchange can be retried after approval.
func (s *Service) ConsumeRegistrationToken(ctx context.Context, plaintext string) (*types.Cluster, error) {
	var cluster *types.Cluster
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		t, err := s.store.ConsumeToken(ctx, tx, HashToken(plaintext), s.now())
		if err != nil {
			return err
		}
		c, err := s.store.GetCluster(ctx, tx, t.ClusterID)
		if err != nil {
			return err
		}
		switch c.State {
		case types.ClusterStateRevoked:
			return ErrClusterRevoked
		case types.ClusterStatePendingApproval:
			return ErrClusterNotPending
		}
		cluster = c
		return nil
	})
	if err != nil {
		return nil, err
	}
	return cluster, nil
}

// MarkRegistered records the provisioned identity and reported metadata and
// flips the cluster active (registration exchange, plan §5.3 step 1).
func (s *Service) MarkRegistered(ctx context.Context, actor, clusterID, clientID, k8sVersion string, labels map[string]string) error {
	c, err := s.store.GetCluster(ctx, s.db.Pool, clusterID)
	if err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.MarkRegistered(ctx, tx, clusterID, clientID, k8sVersion, labels); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: c.OrgID, Actor: actor, Action: "cluster.registered", ObjectType: "cluster", ObjectID: clusterID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, c.OrgID, types.EventClusterRegistered, types.ClusterPayload{
			OrgID: c.OrgID, ClusterID: clusterID, Name: c.Name,
		})
	})
}

// RecordHeartbeat refreshes connection health for a connected agent.
func (s *Service) RecordHeartbeat(ctx context.Context, clusterID string) error {
	return s.store.TouchLastSeen(ctx, s.db.Pool, clusterID)
}

// SetMetadata records agent-reported distribution and OIDC issuer metadata.
func (s *Service) SetMetadata(ctx context.Context, clusterID, distribution, oidcIssuerURL string) error {
	return s.store.SetMetadata(ctx, s.db.Pool, clusterID, distribution, oidcIssuerURL)
}

// SetCapabilityChecksum stores the last acknowledged capability checksum
// (checksum-based resync input, plan §5.2).
func (s *Service) SetCapabilityChecksum(ctx context.Context, clusterID, checksum string) error {
	return s.store.SetCapabilityChecksum(ctx, s.db.Pool, clusterID, checksum)
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

func newUUID() string {
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	buf[6] = (buf[6] & 0x0f) | 0x40
	buf[8] = (buf[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", buf[0:4], buf[4:6], buf[6:8], buf[8:10], buf[10:16])
}
