// Step implementations for the zone state machine (plan §5.12). Each step
// is idempotent: async AWS/MR handles live in step.ExternalRef, so a
// restart resumes polling instead of re-creating (§10 zombie-zone
// mitigation).
package tenantzonefactory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/7K-Inari/inari-server/internal/types"
)

func stepPreflight(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	count, err := env.AWS.CountAccounts(ctx, rc.Zone.OUID)
	if err != nil {
		return false, fmt.Errorf("tzf: preflight quota check: %w", err)
	}
	reasons := Preflight(PreflightInput{
		Slug:           rc.Zone.Slug,
		Region:         rc.Zone.Region,
		Tier:           rc.Zone.Tier,
		OUID:           rc.Zone.OUID,
		AccountCount:   count,
		AccountQuota:   env.Config.AccountQuota,
		AllowedRegions: env.Config.AllowedRegions,
		AllowedTiers:   env.Config.AllowedTiers,
		RequiredTags:   env.Config.RequiredTags,
		Tags:           rc.Zone.Tags,
	})
	if len(reasons) > 0 {
		step.Detail, _ = json.Marshal(map[string]any{"reasons": reasons})
		return false, fmt.Errorf("%w: %s", ErrPreflightDenied, strings.Join(reasons, "; "))
	}
	return true, nil
}

func stepAccountVend(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if step.ExternalRef == "" {
		res, err := env.AWS.CreateAccount(ctx, rc.Zone.Slug, rc.Zone.Slug+"@inari-zones.local", rc.Zone.OUID, rc.Zone.Tags, rc.Zone.ID)
		if err != nil {
			return false, fmt.Errorf("tzf: create account: %w", err)
		}
		step.ExternalRef = res.RequestID
		return false, nil
	}
	st, err := env.AWS.DescribeCreateAccountStatus(ctx, step.ExternalRef)
	if err != nil {
		return false, err
	}
	switch st.State {
	case "SUCCEEDED":
		// OU placement happens after the async vend completes — the account
		// ID is empty until then. Detail flag makes the move idempotent.
		var d struct {
			AWSAccountID string `json:"awsAccountId"`
			Moved        bool   `json:"moved"`
		}
		_ = json.Unmarshal(step.Detail, &d)
		if rc.Zone.OUID != "" && !d.Moved {
			if err := env.AWS.MoveAccount(ctx, st.AccountID, rc.Zone.OUID); err != nil {
				return false, fmt.Errorf("tzf: move account to ou: %w", err)
			}
			d.Moved = true
		}
		rc.Zone.AWSAccountID = st.AccountID
		d.AWSAccountID = st.AccountID
		step.Detail, _ = json.Marshal(d)
		return true, nil
	case "FAILED":
		return false, fmt.Errorf("tzf: account vend failed: %s", st.FailureReason)
	default:
		return false, nil
	}
}

func stepTrustBootstrap(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if rc.Zone.AWSAccountID == "" {
		return false, fmt.Errorf("tzf: trust bootstrap before account vend")
	}
	arn, err := env.Bootstrap.EnsureOIDCRole(ctx, rc.Zone.AWSAccountID, env.Config.IssuerURL, "")
	if err != nil {
		return false, fmt.Errorf("tzf: trust bootstrap: %w", err)
	}
	step.Detail, _ = json.Marshal(map[string]string{"roleArn": arn})
	return true, nil
}

func stepEKSProvision(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if step.ExternalRef == "" {
		ref, err := env.Prov.ApplyEKSMR(ctx, rc.Zone.AWSAccountID, rc.Zone.Region, rc.Zone.Tier)
		if err != nil {
			return false, fmt.Errorf("tzf: eks provision: %w", err)
		}
		step.ExternalRef = ref
		return false, nil
	}
	ready, err := env.Prov.MRStatus(ctx, step.ExternalRef)
	if err != nil {
		return false, err
	}
	return ready, nil
}

func stepInariWiring(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	var roleARN string
	if tb := rc.Steps[types.ZoneStepTrustBootstrap]; tb != nil {
		var d struct {
			RoleARN string `json:"roleArn"`
		}
		_ = json.Unmarshal(tb.Detail, &d)
		roleARN = d.RoleARN
	}
	res, err := env.Wiring.WireZone(ctx, rc.Zone, roleARN)
	if err != nil {
		return false, fmt.Errorf("tzf: inari wiring: %w", err)
	}
	rc.Zone.OrgID = res.OrgID
	rc.Zone.KeycloakOrgID = res.KeycloakOrgID
	rc.Zone.ClusterID = res.ClusterID
	rc.Zone.CloudAccountID = res.CloudAccountID
	rc.Zone.GitRepo = res.GitRepo
	step.Detail, _ = json.Marshal(res)
	return true, nil
}

func stepCordon(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if rc.Zone.ClusterID == "" {
		step.Status = types.ZoneStepSkipped
		return true, nil
	}
	if err := env.Clusters.Cordon(ctx, rc.Actor, rc.Zone.ClusterID); err != nil {
		return false, fmt.Errorf("tzf: cordon: %w", err)
	}
	return true, nil
}

func stepDrain(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if rc.Zone.ClusterID == "" {
		step.Status = types.ZoneStepSkipped
		return true, nil
	}
	drained, err := env.Clusters.Decommission(ctx, rc.Actor, rc.Zone.ClusterID, false)
	if err != nil {
		return false, fmt.Errorf("tzf: drain: %w", err)
	}
	step.Detail, _ = json.Marshal(map[string][]string{"drainedInstanceIds": drained})
	return true, nil
}

func stepEKSDelete(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	prov := rc.Steps[types.ZoneStepEKSProvision]
	if prov == nil || prov.ExternalRef == "" {
		step.Status = types.ZoneStepSkipped
		return true, nil
	}
	if step.ExternalRef == "" {
		if err := env.Prov.DeleteMR(ctx, prov.ExternalRef); err != nil {
			return false, fmt.Errorf("tzf: eks delete: %w", err)
		}
		step.ExternalRef = prov.ExternalRef
		return false, nil
	}
	gone, err := env.Prov.MRDeleted(ctx, step.ExternalRef)
	if err != nil {
		return false, err
	}
	return gone, nil
}

func stepAccountClose(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if rc.Zone.AWSAccountID == "" {
		step.Status = types.ZoneStepSkipped
		return true, nil
	}
	if step.ExternalRef != "" {
		// Close was already accepted by AWS; there is no close-status API to
		// poll (DescribeCreateAccountStatus only tracks create requests), so
		// acceptance is terminal for the state machine.
		return true, nil
	}
	res, err := env.AWS.CloseAccount(ctx, rc.Zone.AWSAccountID)
	if err != nil {
		return false, fmt.Errorf("tzf: close account: %w", err)
	}
	step.ExternalRef = res.RequestID
	return true, nil
}
func stepIdentityRevoke(ctx context.Context, env *Env, rc *RunContext, step *types.TenantZoneStep) (bool, error) {
	if err := env.Wiring.UnwireZone(ctx, rc.Zone); err != nil {
		return false, fmt.Errorf("tzf: identity revoke: %w", err)
	}
	return true, nil
}

// stepAuditArchive is a no-op at the step level — the Service writes the
// archived audit trail when the zone flips to closed.
func stepAuditArchive(context.Context, *Env, *RunContext, *types.TenantZoneStep) (bool, error) {
	return true, nil
}
