// Package cloudaccounts implements the Cloud Accounts module (plan §5.7,
// AWS onboarding first): a tenant registers an AWS account by IAM role ARN +
// external ID (never keys — §4.1, §5.10), the control plane validates the
// trust via an STS AssumeRole dry-run, and Crossplane ProviderConfigs are
// rendered per workload cluster (IRSA vs web identity).
//
// The CloudAccount entity and this Service API are a PUBLIC CONTRACT for the
// M3-W2 Tenant Zone Factory (management-scope accounts, trust bootstrap).
// Keep signatures stable; extend additively.
package cloudaccounts

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/7K-Inari/inari-server/internal/audit"
	"github.com/7K-Inari/inari-server/internal/db"
	"github.com/7K-Inari/inari-server/internal/types"
)

var (
	ErrNotFound          = errors.New("cloud account not found")
	ErrAlreadyRegistered = errors.New("cloud account already registered for this tenant")
	ErrInvalidState      = errors.New("cloud account in invalid state")
	// ErrInvalidInput wraps all request-shape validation failures so handlers
	// can map them to 422.
	ErrInvalidInput = errors.New("invalid cloud account input")
)

// RegisterInput carries everything needed to register a cloud account. Only
// account ID, role ARN, external ID and issuer metadata are ever persisted.
type RegisterInput struct {
	Provider   string // "aws" (default when empty)
	AccountID  string // 12-digit AWS account ID
	RoleARN    string // arn:aws:iam::<acct>:role/...
	ExternalID string // optional STS external ID
	IssuerURL  string // optional OIDC issuer metadata
	RunContext string // "tenant" (default) | "platform"
}

var (
	accountIDRe = regexp.MustCompile(`^\d{12}$`)
	roleARNRe   = regexp.MustCompile(`^arn:aws:iam::\d{12}:role/[A-Za-z0-9+=,.@_/-]+$`)
)

// validateRegisterInput checks the input shape and applies defaults. Pure.
func validateRegisterInput(in *RegisterInput) error {
	if in.Provider == "" {
		in.Provider = "aws"
	}
	if in.Provider != "aws" {
		return fmt.Errorf("%w: unsupported provider %q (only aws)", ErrInvalidInput, in.Provider)
	}
	if !accountIDRe.MatchString(in.AccountID) {
		return fmt.Errorf("%w: account ID must be 12 digits, got %q", ErrInvalidInput, in.AccountID)
	}
	if !roleARNRe.MatchString(in.RoleARN) {
		return fmt.Errorf("%w: role ARN must match arn:aws:iam::<account>:role/<name>, got %q", ErrInvalidInput, in.RoleARN)
	}
	if arnAcct := in.RoleARN[len("arn:aws:iam::") : len("arn:aws:iam::")+12]; arnAcct != in.AccountID {
		return fmt.Errorf("%w: account ID %q does not match role ARN account %q", ErrInvalidInput, in.AccountID, arnAcct)
	}
	if len(in.ExternalID) > 1224 { // AWS STS ExternalId maximum
		return fmt.Errorf("%w: external ID exceeds 1224 characters", ErrInvalidInput)
	}
	if in.IssuerURL != "" && !strings.HasPrefix(in.IssuerURL, "https://") {
		return fmt.Errorf("%w: issuer URL must be an https:// URL, got %q", ErrInvalidInput, in.IssuerURL)
	}
	if in.RunContext == "" {
		in.RunContext = types.CloudAccountRunContextTenant
	}
	if in.RunContext != types.CloudAccountRunContextTenant && in.RunContext != types.CloudAccountRunContextPlatform {
		return fmt.Errorf("%w: run context must be tenant|platform, got %q", ErrInvalidInput, in.RunContext)
	}
	return nil
}

// Store is the PostgreSQL projection of cloud account state.
type Store struct{}

func NewStore() *Store { return &Store{} }

const accountCols = `id, org_id, provider, account_id, role_arn, external_id, issuer_url, run_context,
	state, validated_at, validation_error, created_by, created_at`

func scanAccount(row interface{ Scan(...any) error }) (*types.CloudAccount, error) {
	var a types.CloudAccount
	err := row.Scan(&a.ID, &a.OrgID, &a.Provider, &a.AccountID, &a.RoleARN, &a.ExternalID,
		&a.IssuerURL, &a.RunContext, &a.State, &a.ValidatedAt, &a.ValidationErr, &a.CreatedBy, &a.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func (s *Store) CreateAccount(ctx context.Context, q db.Querier, a *types.CloudAccount) error {
	const sql = `INSERT INTO cloud_accounts (id, org_id, provider, account_id, role_arn, external_id, issuer_url, run_context, state, created_by)
	             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING ` + accountCols
	out, err := scanAccount(q.QueryRow(ctx, sql, a.ID, a.OrgID, a.Provider, a.AccountID, a.RoleARN,
		a.ExternalID, a.IssuerURL, a.RunContext, a.State, a.CreatedBy))
	if isUniqueViolation(err) {
		return ErrAlreadyRegistered
	}
	if err != nil {
		return err
	}
	*a = *out
	return nil
}

func (s *Store) GetAccount(ctx context.Context, q db.Querier, id string) (*types.CloudAccount, error) {
	const sql = `SELECT ` + accountCols + ` FROM cloud_accounts WHERE id = $1`
	a, err := scanAccount(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *Store) ListAccounts(ctx context.Context, q db.Querier, orgID string) ([]types.CloudAccount, error) {
	const sql = `SELECT ` + accountCols + ` FROM cloud_accounts WHERE org_id = $1 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []types.CloudAccount
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// SetValidationState records the outcome of a validation run.
func (s *Store) SetValidationState(ctx context.Context, q db.Querier, id, state string, validatedAt *time.Time, validationErr string) error {
	const sql = `UPDATE cloud_accounts SET state = $2, validated_at = $3, validation_error = $4 WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id, state, validatedAt, validationErr)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) DeleteAccount(ctx context.Context, q db.Querier, id string) error {
	const sql = `DELETE FROM cloud_accounts WHERE id = $1`
	tag, err := q.Exec(ctx, sql, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Service orchestrates cloud account lifecycle: DB projection + audit +
// outbox in one TX; trust validation via the STSValidator seam.
type Service struct {
	db        *db.DB
	store     *Store
	audit     *audit.Store
	validator STSValidator
}

// NewService wires the module. validator may be a DisabledValidator when the
// platform has no AWS token source (accounts then stay pending_validation).
func NewService(d *db.DB, store *Store, auditStore *audit.Store, validator STSValidator) *Service {
	if validator == nil {
		validator = DisabledValidator{}
	}
	return &Service{db: d, store: store, audit: auditStore, validator: validator}
}

// Register validates the input and inserts the account in pending_validation
// state, with audit + outbox in one TX. A duplicate (org, provider,
// account_id) returns ErrAlreadyRegistered.
func (s *Service) Register(ctx context.Context, actor, orgID string, in RegisterInput) (*types.CloudAccount, error) {
	if err := validateRegisterInput(&in); err != nil {
		return nil, err
	}
	a := &types.CloudAccount{
		ID:         "cloudaccount:" + newUUID(),
		OrgID:      orgID,
		Provider:   in.Provider,
		AccountID:  in.AccountID,
		RoleARN:    in.RoleARN,
		ExternalID: in.ExternalID,
		IssuerURL:  in.IssuerURL,
		RunContext: in.RunContext,
		State:      types.CloudAccountStatePendingValidation,
		CreatedBy:  actor,
	}
	err := s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.CreateAccount(ctx, tx, a); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cloud_account.registered", ObjectType: "cloud_account", ObjectID: a.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventCloudAccountRegistered, types.CloudAccountPayload{
			OrgID: orgID, AccountID: a.ID, AWSAcct: a.AccountID, State: a.State,
		})
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Validate runs the STS AssumeRole dry-run against the registered role. On
// success the account becomes active (validated_at set); on failure it
// becomes invalid with validation_error recorded. Both outcomes persist
// state + audit + outbox in one TX and return the account with a nil error.
// When the platform has no token source (DisabledValidator) the account is
// left pending_validation and ErrValidationUnavailable is returned.
func (s *Service) Validate(ctx context.Context, actor, orgID, id string) (*types.CloudAccount, error) {
	a, err := s.store.GetAccount(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if a.OrgID != orgID {
		return nil, ErrNotFound
	}
	dryRunErr := s.validator.AssumeRoleDryRun(ctx, a.RoleARN, a.ExternalID, a.IssuerURL)
	if errors.Is(dryRunErr, ErrValidationUnavailable) {
		return nil, fmt.Errorf("cloudaccounts: validate %s: %w", id, ErrValidationUnavailable)
	}
	now := time.Now()
	if dryRunErr == nil {
		a.State = types.CloudAccountStateActive
		a.ValidatedAt = &now
		a.ValidationErr = ""
	} else {
		a.State = types.CloudAccountStateInvalid
		a.ValidationErr = dryRunErr.Error()
	}
	err = s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.SetValidationState(ctx, tx, a.ID, a.State, a.ValidatedAt, a.ValidationErr); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cloud_account.validated", ObjectType: "cloud_account", ObjectID: a.ID,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventCloudAccountValidated, types.CloudAccountPayload{
			OrgID: orgID, AccountID: a.ID, AWSAcct: a.AccountID, State: a.State,
		})
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// Get returns one account scoped to the org (cross-tenant IDs yield
// ErrNotFound).
func (s *Service) Get(ctx context.Context, orgID, id string) (*types.CloudAccount, error) {
	a, err := s.store.GetAccount(ctx, s.db.Pool, id)
	if err != nil {
		return nil, err
	}
	if a.OrgID != orgID {
		return nil, ErrNotFound
	}
	return a, nil
}

// List returns all accounts of an org.
func (s *Service) List(ctx context.Context, orgID string) ([]types.CloudAccount, error) {
	return s.store.ListAccounts(ctx, s.db.Pool, orgID)
}

// Deregister deletes the control-plane record (audit + outbox in one TX).
// Revoking AWS-side trust is separate and tenant-owned: the tenant deletes
// the IAM role.
func (s *Service) Deregister(ctx context.Context, actor, orgID, id string) error {
	a, err := s.store.GetAccount(ctx, s.db.Pool, id)
	if err != nil {
		return err
	}
	if a.OrgID != orgID {
		return ErrNotFound
	}
	return s.db.WithTx(ctx, func(tx pgx.Tx) error {
		if err := s.store.DeleteAccount(ctx, tx, id); err != nil {
			return err
		}
		if err := s.audit.Record(ctx, tx, &types.AuditEvent{
			OrgID: orgID, Actor: actor, Action: "cloud_account.deregistered", ObjectType: "cloud_account", ObjectID: id,
		}); err != nil {
			return err
		}
		return audit.AppendOutbox(ctx, tx, orgID, types.EventCloudAccountDeregistered, types.CloudAccountPayload{
			OrgID: orgID, AccountID: id, AWSAcct: a.AccountID,
		})
	})
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
