// Deterministic in-memory fakes for the AWS/Crossplane seams. These are
// the M3 acceptance-test backends (plan §10: the state machine is fully
// tested without real AWS); failures and async latency are scriptable.
package tenantzonefactory

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

// FakeOrganizations is a deterministic in-memory Organizations impl.
// Operations start InProgress and succeed after SucceedAfterPolls polls;
// FailNext makes the next operation of that kind fail (retry testing).
type FakeOrganizations struct {
	mu                sync.Mutex
	nextAcct          int
	requests          map[string]*fakeRequest
	accounts          map[string]int // ouID -> count
	SucceedAfterPolls int
	FailCreate        bool
	FailClose         bool
	created           []string // account IDs, in creation order
}

type fakeRequest struct {
	kind      string // create | close
	accountID string
	polls     int
	succeedAt int
	fail      bool
	closed    bool
}

// NewFakeOrganizations returns a fake whose async operations succeed after
// one poll by default.
func NewFakeOrganizations() *FakeOrganizations {
	return &FakeOrganizations{
		requests:          map[string]*fakeRequest{},
		accounts:          map[string]int{},
		SucceedAfterPolls: 1,
	}
}

// CreateAccount implements Organizations.
func (f *FakeOrganizations) CreateAccount(_ context.Context, name, _, ouID string, _ map[string]string) (*CreateAccountResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextAcct++
	id := fmt.Sprintf("%012d", 100000000000+f.nextAcct)
	rid := fmt.Sprintf("car-%d", f.nextAcct)
	f.requests[rid] = &fakeRequest{kind: "create", accountID: id, succeedAt: f.SucceedAfterPolls, fail: f.FailCreate}
	f.accounts[ouID]++
	f.created = append(f.created, id)
	_ = name
	return &CreateAccountResult{RequestID: rid}, nil
}

// DescribeCreateAccountStatus implements Organizations.
func (f *FakeOrganizations) DescribeCreateAccountStatus(_ context.Context, requestID string) (*AccountStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[requestID]
	if !ok {
		return nil, fmt.Errorf("tzf: unknown request %q", requestID)
	}
	r.polls++
	if r.fail {
		return &AccountStatus{State: "FAILED", FailureReason: "scripted failure"}, nil
	}
	if r.polls >= r.succeedAt {
		if r.kind == "close" {
			r.closed = true
			return &AccountStatus{State: "SUCCEEDED", AccountID: r.accountID}, nil
		}
		return &AccountStatus{State: "SUCCEEDED", AccountID: r.accountID}, nil
	}
	return &AccountStatus{State: "IN_PROGRESS"}, nil
}

// CloseAccount implements Organizations.
func (f *FakeOrganizations) CloseAccount(_ context.Context, accountID string) (*CreateAccountResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextAcct++
	rid := fmt.Sprintf("car-%d", f.nextAcct)
	f.requests[rid] = &fakeRequest{kind: "close", accountID: accountID, succeedAt: f.SucceedAfterPolls, fail: f.FailClose}
	return &CreateAccountResult{RequestID: rid}, nil
}

// CountAccounts implements Organizations.
func (f *FakeOrganizations) CountAccounts(_ context.Context, ouID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.accounts[ouID], nil
}

// CreatedAccounts returns vended account IDs in creation order (assertions).
func (f *FakeOrganizations) CreatedAccounts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.created...)
}

// FakeTrustBootstrap records OIDC-role bootstraps.
type FakeTrustBootstrap struct {
	Roles map[string]string // accountID -> roleARN
	Err   error
}

// NewFakeTrustBootstrap returns an empty fake.
func NewFakeTrustBootstrap() *FakeTrustBootstrap {
	return &FakeTrustBootstrap{Roles: map[string]string{}}
}

// EnsureOIDCRole implements TrustBootstrap (idempotent per account).
func (f *FakeTrustBootstrap) EnsureOIDCRole(_ context.Context, accountID, _, roleName string) (string, error) {
	if f.Err != nil {
		return "", f.Err
	}
	if arn, ok := f.Roles[accountID]; ok {
		return arn, nil
	}
	if roleName == "" {
		roleName = "inari-onboarding"
	}
	arn := fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
	f.Roles[accountID] = arn
	return arn, nil
}

// FakeProvisioner is a deterministic in-memory Provisioner. MRs become
// ready after ReadyAfterPolls status checks.
type FakeProvisioner struct {
	mu              sync.Mutex
	next            int
	mrs             map[string]*fakeMR
	ReadyAfterPolls int
	FailApply       bool
}

type fakeMR struct {
	polls   int
	readyAt int
	deleted bool
}

// NewFakeProvisioner returns a fake whose MRs are ready after one poll.
func NewFakeProvisioner() *FakeProvisioner {
	return &FakeProvisioner{mrs: map[string]*fakeMR{}, ReadyAfterPolls: 1}
}

// ApplyEKSMR implements Provisioner.
func (f *FakeProvisioner) ApplyEKSMR(_ context.Context, accountID, region, tier string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailApply {
		return "", errors.New("tzf: scripted MR apply failure")
	}
	f.next++
	ref := fmt.Sprintf("eks-%s-%s-%d", accountID, region, f.next)
	f.mrs[ref] = &fakeMR{readyAt: f.ReadyAfterPolls}
	_ = tier
	return ref, nil
}

// MRStatus implements Provisioner.
func (f *FakeProvisioner) MRStatus(_ context.Context, ref string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mr, ok := f.mrs[ref]
	if !ok {
		return false, fmt.Errorf("tzf: unknown MR %q", ref)
	}
	mr.polls++
	return mr.polls >= mr.readyAt, nil
}

// DeleteMR implements Provisioner.
func (f *FakeProvisioner) DeleteMR(_ context.Context, ref string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	mr, ok := f.mrs[ref]
	if !ok {
		return fmt.Errorf("tzf: unknown MR %q", ref)
	}
	mr.deleted = true
	return nil
}

// MRDeleted implements Provisioner.
func (f *FakeProvisioner) MRDeleted(_ context.Context, ref string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	mr, ok := f.mrs[ref]
	if !ok {
		return true, nil
	}
	return mr.deleted, nil
}
