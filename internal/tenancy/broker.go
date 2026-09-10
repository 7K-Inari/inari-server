// IdP brokering service and projection store (Settings design §3.3,
// OIDC-only v1). Mirrors the §3.1 identity-client pattern: Keycloak-first
// writes, DB projection + audit in one TX, best-effort Keycloak rollback.
// The client secret is write-only in Keycloak and never persisted,
// returned, or logged server-side. One IdP per org in v1.
package tenancy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrBrokerNotFound = errors.New("identity provider not found")
	ErrBrokerExists   = errors.New("organization already has an identity provider")
	ErrDomainTaken    = errors.New("domain already used by another organization")
	ErrInvalidDomain  = errors.New("invalid domain hint")
)

// IdentityProviderManager abstracts the Keycloak Admin IdP brokering CRUD
// (implemented by KeycloakAdmin; faked in tests).
type IdentityProviderManager interface {
	CreateIdP(ctx context.Context, spec BrokerIdPSpec) error
	UpdateIdP(ctx context.Context, spec BrokerIdPSpec) error
	DeleteIdP(ctx context.Context, alias string) error
	LinkIdPToOrg(ctx context.Context, kcOrgID, alias string) error
	UnlinkIdPFromOrg(ctx context.Context, kcOrgID, alias string) error
	SetOrgDomains(ctx context.Context, kcOrgID string, domains []string) error
}

// WithIdentityProviderManager wires the Keycloak IdP brokering backend used
// by the broker routes.
func (s *Service) WithIdentityProviderManager(m IdentityProviderManager) *Service {
	s.brokers = m
	return s
}

// brokeredIdPAlias renders the org-scoped KC IdP alias org-<org>-<alias>.
func brokeredIdPAlias(slug, alias string) string {
	return "org-" + slug + "-" + alias
}

// domainHintRe validates org email domains: 2-10 dot-separated lowercase
// labels with an optional leading "*." wildcard.
var domainHintRe = regexp.MustCompile(`^(\*\.)?[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?){1,9}$`)

func validateDomainHints(hints []string) error {
	for _, h := range hints {
		if !domainHintRe.MatchString(h) {
			return fmt.Errorf("%w: %q", ErrInvalidDomain, h)
		}
	}
	return nil
}

func (s *Service) brokerSpec(slug string, b *types.BrokeredIdP, secret string) BrokerIdPSpec {
	return BrokerIdPSpec{
		Alias:        brokeredIdPAlias(slug, b.Alias),
		IssuerURL:    b.IssuerURL,
		ClientID:     b.ClientID,
		ClientSecret: secret,
		EmailClaim:   b.ClaimMapping.Email,
		GroupsClaim:  b.ClaimMapping.Groups,
		OrgGroupPath: GroupPath(slug, "members"),
	}
}

// orgDomains renders the KC org domain list: the <slug>.inari.local
// placeholder plus the tenant's hints.
func orgDomains(slug string, hints []string) []string {
	return append([]string{slug + ".inari.local"}, hints...)
}

// CreateBrokeredIdP provisions the Keycloak IdP, links it to the org, sets
// the org's email domains, then records the metadata projection + audit in
// one TX. The client secret is passed to Keycloak only.
func (s *Service) CreateBrokeredIdP(ctx context.Context, actor, slug string, in *types.BrokeredIdP, clientSecret string) (*types.BrokeredIdP, error) {
	if s.brokers == nil {
		return nil, errors.New("tenancy: identity provider manager not configured")
	}
	if !strings.HasPrefix(in.IssuerURL, "https://") {
		return nil, fmt.Errorf("tenancy: issuer URL must be https")
	}
	if err := validateDomainHints(in.DomainHints); err != nil {
		return nil, err
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	// Fast-path one-IdP-per-org check against the projection so a duplicate
	// fails before any Keycloak write.
	if _, err := s.store.GetIdPBrokerByOrg(ctx, s.db.Pool, org.ID); err == nil {
		return nil, ErrBrokerExists
	} else if !errors.Is(err, ErrBrokerNotFound) {
		return nil, err
	}
	broker := &types.BrokeredIdP{
		Alias:        in.Alias,
		OrgID:        org.ID,
		IssuerURL:    in.IssuerURL,
		ClientID:     in.ClientID,
		ClaimMapping: in.ClaimMapping,
		DomainHints:  in.DomainHints,
	}
	kcAlias := brokeredIdPAlias(slug, broker.Alias)
	if err := s.brokers.CreateIdP(ctx, s.brokerSpec(slug, broker, clientSecret)); err != nil {
		return nil, fmt.Errorf("tenancy: create keycloak identity provider: %w", err)
	}
	if err := s.brokers.LinkIdPToOrg(ctx, org.KeycloakOrgID, kcAlias); err != nil {
		s.rollbackIdP(ctx, org.KeycloakOrgID, kcAlias)
		return nil, fmt.Errorf("tenancy: link identity provider: %w", err)
	}
	if err := s.brokers.SetOrgDomains(ctx, org.KeycloakOrgID, orgDomains(slug, broker.DomainHints)); err != nil {
		s.rollbackIdP(ctx, org.KeycloakOrgID, kcAlias)
		return nil, err
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateIdPBroker(ctx, tx, broker); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "idp.broker.created", ObjectType: "idp_broker", ObjectID: kcAlias,
			Payload: mustJSON(types.IdPBrokerPayload{OrgID: org.ID, Alias: kcAlias}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventIdPBrokerCreated, types.IdPBrokerPayload{
			OrgID: org.ID, Alias: kcAlias,
		})
	})
	if err != nil {
		s.rollbackIdP(ctx, org.KeycloakOrgID, kcAlias)
		return nil, err
	}
	return broker, nil
}

// rollbackIdP is the best-effort compensation for the external Keycloak
// writes: unlink the org association first, then delete the instance.
func (s *Service) rollbackIdP(ctx context.Context, kcOrgID, kcAlias string) {
	if err := s.brokers.UnlinkIdPFromOrg(ctx, kcOrgID, kcAlias); err != nil {
		return
	}
	_ = s.brokers.DeleteIdP(ctx, kcAlias)
}

// GetBrokeredIdP returns the org's brokered IdP (at most one in v1).
func (s *Service) GetBrokeredIdP(ctx context.Context, slug, alias string) (*types.BrokeredIdP, error) {
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return nil, err
	}
	broker, err := s.store.GetIdPBrokerByOrg(ctx, s.db.Pool, org.ID)
	if err != nil {
		return nil, err
	}
	if alias != "" && broker.Alias != alias {
		return nil, ErrBrokerNotFound
	}
	return broker, nil
}

// ListBrokeredIdPs returns the org's brokered IdPs (0 or 1 in v1).
func (s *Service) ListBrokeredIdPs(ctx context.Context, orgID string) ([]types.BrokeredIdP, error) {
	return s.store.ListIdPBrokers(ctx, s.db.Pool, orgID)
}

// UpdateBrokeredIdP applies a full metadata update to Keycloak and the
// projection; clientSecret rotates the KC secret when non-empty.
func (s *Service) UpdateBrokeredIdP(ctx context.Context, actor, slug string, broker *types.BrokeredIdP, clientSecret string) error {
	if s.brokers == nil {
		return errors.New("tenancy: identity provider manager not configured")
	}
	if !strings.HasPrefix(broker.IssuerURL, "https://") {
		return fmt.Errorf("tenancy: issuer URL must be https")
	}
	if err := validateDomainHints(broker.DomainHints); err != nil {
		return err
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	kcAlias := brokeredIdPAlias(slug, broker.Alias)
	if err := s.brokers.UpdateIdP(ctx, s.brokerSpec(slug, broker, clientSecret)); err != nil {
		return fmt.Errorf("tenancy: update keycloak identity provider: %w", err)
	}
	if err := s.brokers.SetOrgDomains(ctx, org.KeycloakOrgID, orgDomains(slug, broker.DomainHints)); err != nil {
		return err
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.UpdateIdPBroker(ctx, tx, broker); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: org.ID, Actor: actor, Action: "idp.broker.updated", ObjectType: "idp_broker", ObjectID: kcAlias,
			Payload: mustJSON(types.IdPBrokerPayload{OrgID: org.ID, Alias: kcAlias}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, org.ID, types.EventIdPBrokerUpdated, types.IdPBrokerPayload{
			OrgID: org.ID, Alias: kcAlias,
		})
	})
}

// DeleteBrokeredIdP unlinks the org association first (unlinked IdPs have
// their org-group mappings skipped at runtime), deletes the Keycloak
// instance, then removes the projection with audit.
func (s *Service) DeleteBrokeredIdP(ctx context.Context, actor, slug, alias string) error {
	if s.brokers == nil {
		return errors.New("tenancy: identity provider manager not configured")
	}
	broker, err := s.GetBrokeredIdP(ctx, slug, alias)
	if err != nil {
		return err
	}
	org, err := s.store.GetOrganizationBySlug(ctx, s.db.Pool, slug)
	if err != nil {
		return err
	}
	kcAlias := brokeredIdPAlias(slug, broker.Alias)
	if err := s.brokers.UnlinkIdPFromOrg(ctx, org.KeycloakOrgID, kcAlias); err != nil {
		return fmt.Errorf("tenancy: unlink identity provider: %w", err)
	}
	if err := s.brokers.DeleteIdP(ctx, kcAlias); err != nil {
		return fmt.Errorf("tenancy: delete keycloak identity provider: %w", err)
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeleteIdPBroker(ctx, tx, broker.OrgID, broker.Alias); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: broker.OrgID, Actor: actor, Action: "idp.broker.deleted", ObjectType: "idp_broker", ObjectID: kcAlias,
			Payload: mustJSON(types.IdPBrokerPayload{OrgID: broker.OrgID, Alias: kcAlias}),
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, broker.OrgID, types.EventIdPBrokerDeleted, types.IdPBrokerPayload{
			OrgID: broker.OrgID, Alias: kcAlias,
		})
	})
}

// CreateIdPBroker inserts the metadata projection row (never the secret).
func (s *Store) CreateIdPBroker(ctx context.Context, q db.Querier, b *types.BrokeredIdP) error {
	const sql = `INSERT INTO idp_brokers (org_id, alias, issuer_url, client_id, claim_mapping, domain_hints)
	             VALUES ($1,$2,$3,$4,$5,$6) RETURNING created_at`
	err := q.QueryRow(ctx, sql, b.OrgID, b.Alias, b.IssuerURL, b.ClientID,
		mustJSON(b.ClaimMapping), nonEmptyJSON(b.DomainHints)).Scan(&b.CreatedAt)
	if isUniqueViolation(err) {
		return ErrBrokerExists
	}
	return err
}

func (s *Store) GetIdPBrokerByOrg(ctx context.Context, q db.Querier, orgID string) (*types.BrokeredIdP, error) {
	const sql = `SELECT alias, org_id, issuer_url, client_id, claim_mapping, domain_hints, created_at
	             FROM idp_brokers WHERE org_id = $1`
	return scanIdPBroker(q.QueryRow(ctx, sql, orgID))
}

func (s *Store) ListIdPBrokers(ctx context.Context, q db.Querier, orgID string) ([]types.BrokeredIdP, error) {
	const sql = `SELECT alias, org_id, issuer_url, client_id, claim_mapping, domain_hints, created_at
	             FROM idp_brokers WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.BrokeredIdP
	for rows.Next() {
		b, err := scanIdPBroker(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *b)
	}
	return out, rows.Err()
}

// UpdateIdPBroker rewrites the mutable metadata fields.
func (s *Store) UpdateIdPBroker(ctx context.Context, q db.Querier, b *types.BrokeredIdP) error {
	const sql = `UPDATE idp_brokers SET issuer_url=$3, client_id=$4, claim_mapping=$5, domain_hints=$6, updated_at=now()
	             WHERE org_id=$1 AND alias=$2`
	_, err := q.Exec(ctx, sql, b.OrgID, b.Alias, b.IssuerURL, b.ClientID,
		mustJSON(b.ClaimMapping), nonEmptyJSON(b.DomainHints))
	return err
}

func (s *Store) DeleteIdPBroker(ctx context.Context, q db.Querier, orgID, alias string) error {
	const sql = `DELETE FROM idp_brokers WHERE org_id=$1 AND alias=$2`
	_, err := q.Exec(ctx, sql, orgID, alias)
	return err
}

func scanIdPBroker(row rowScanner) (*types.BrokeredIdP, error) {
	var b types.BrokeredIdP
	var mapping, hints []byte
	err := row.Scan(&b.Alias, &b.OrgID, &b.IssuerURL, &b.ClientID, &mapping, &hints, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrBrokerNotFound
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(mapping, &b.ClaimMapping); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(hints, &b.DomainHints); err != nil {
		return nil, err
	}
	return &b, nil
}
