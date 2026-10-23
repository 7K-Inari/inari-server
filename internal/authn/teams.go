package authn

import (
	"github.com/7K-Inari/inari-server/internal/types"
)

// CallerTeamIDs resolves the caller's team IDs inside an org by matching
// the identity's Keycloak full-path group claims (/tenant-<slug>/<team>)
// against the org's teams (plan §5.4 group convention; decision 5 of the
// multi-repo design — identity-side matching, no FGA round-trip).
func CallerTeamIDs(id *Identity, teams []types.Team) []string {
	if id == nil {
		return nil
	}
	inGroups := map[string]bool{}
	for _, g := range id.Groups {
		inGroups[g] = true
	}
	var out []string
	for _, t := range teams {
		if inGroups[t.KeycloakGroupPath] {
			out = append(out, t.ID)
		}
	}
	return out
}
