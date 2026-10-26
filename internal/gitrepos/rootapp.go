// Root-app attachment (Feature A §3): a team repo goes live by committing an
// ArgoCD Application into the org's baseline repo at
// gitops-repos/<name>/root-app.yaml; the baseline root app already syncs that
// path, so ArgoCD (not the agent) pulls the team repo. The agent's
// single-repo write constraint is unchanged. M2W1's scaffold
// `attaching-root-app` step reuses AttachRootApp.
package gitrepos

import (
	"context"
	"errors"
	"fmt"

	"github.com/7K-Inari/inari-server/internal/inventory"
	"github.com/7K-Inari/inari-server/internal/orchestrator"
	"github.com/7K-Inari/inari-server/internal/orchestrator/gitprovider"
	"github.com/7K-Inari/inari-server/internal/types"
)

// RootAppPath is the baseline-repo path of a team repo's root Application.
func RootAppPath(name string) string {
	return "gitops-repos/" + name + "/root-app.yaml"
}

// renderTeamRootApp renders the ArgoCD Application attaching a team repo to
// the tenant ArgoCD: source is the team repo itself (path "." — the M2W1
// template skeleton may narrow it), automated/selfHeal/prune so the team
// repo's own root content reconciles without manual intervention.
func renderTeamRootApp(r *types.TenantGitRepo, repoURL string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: inari-repo-%s
  namespace: argocd
spec:
  project: default
  source:
    repoURL: %s
    targetRevision: %s
    path: .
  destination:
    server: https://kubernetes.default.svc
    namespace: argocd
  syncPolicy:
    automated:
      selfHeal: true
      prune: true
`, r.Name, repoURL, r.BaseBranch))
}

// AttachRootApp commits the team repo's root Application into the org's
// default baseline repo. Idempotent: re-committing identical content is a
// no-op for the fake and a same-content commit for real providers. When the
// org has no default baseline yet (team repo registered first), the attach
// is skipped — the root app can be committed once a baseline exists.
func (s *Service) AttachRootApp(ctx context.Context, orgID string, row *types.TenantGitRepo) error {
	baseline, err := s.store.GetDefaultGitRepo(ctx, s.querier(), orgID)
	if errors.Is(err, inventory.ErrRepoNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	git, _, err := s.git.ResolveRow(ctx, baseline)
	if err != nil {
		return err
	}
	file := gitprovider.File{
		Path:    RootAppPath(row.Name),
		Content: renderTeamRootApp(row, orchestrator.RepoURL(row.Repo)),
	}
	message := fmt.Sprintf("attach team repo %s (%s)", row.Name, row.Repo)
	// The baseline's commit policy applies to writes into it. PR-policy
	// baselines get the attach as a direct commit for now (the file is
	// additive and idempotent); a PR flow lands with M2W1's scaffold step.
	if _, err := git.CommitFiles(ctx, baseline.Repo, baseline.BaseBranch, []gitprovider.File{file}, message); err != nil {
		return fmt.Errorf("gitrepos: attach root app: %w", err)
	}
	return nil
}
