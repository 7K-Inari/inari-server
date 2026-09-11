// Keycloak Admin REST implementation of IdP brokering (Settings design
// §3.3, OIDC-only v1). The IdP client secret is write-only: Keycloak masks
// it as ********** on read, and a PUT echoing the masked sentinel preserves
// the existing secret — updates only set clientSecret when rotating.
package tenancy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const idpMaskedSecret = "**********"

// BrokerIdPSpec describes a tenant-scoped OIDC IdP instance brokered into a
// Keycloak Organization (KC alias org-<org>-<alias>).
type BrokerIdPSpec struct {
	Alias        string // full KC alias (org-<org>-<alias>)
	IssuerURL    string
	ClientID     string
	ClientSecret string // write-only; empty on updates that keep the existing secret
	EmailClaim   string
	GroupsClaim  string
	OrgGroupPath string // hardcoded-mapper target, e.g. tenant-<slug>/members
}

// CreateIdP provisions the OIDC IdP instance (two-call write model, part 1)
// and syncs its managed mappers. Idempotent: an existing alias (409) is
// treated as success, mirroring CreateClient.
func (k *KeycloakAdmin) CreateIdP(ctx context.Context, spec BrokerIdPSpec) error {
	// The hardcoded group mapper targets the org members group; create it
	// first so the mapper's group reference resolves.
	if _, err := k.CreateGroup(ctx, spec.OrgGroupPath); err != nil {
		return err
	}
	resp, err := k.do(ctx, http.MethodPost, "/identity-provider/instances", map[string]any{
		"alias":       spec.Alias,
		"providerId":  "oidc",
		"enabled":     true,
		"trustEmail":  true,
		"hideOnLogin": true,
		"config":      idpConfig(spec, spec.ClientSecret),
	})
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak: create identity provider: status %d: %s", resp.StatusCode, b)
	}
	return k.syncIdPMappers(ctx, spec)
}

// UpdateIdP read-modify-writes the IdP representation. The masked secret is
// echoed back unchanged unless spec.ClientSecret rotates it.
func (k *KeycloakAdmin) UpdateIdP(ctx context.Context, spec BrokerIdPSpec) error {
	rep, err := k.getIdPRep(ctx, spec.Alias)
	if err != nil {
		return err
	}
	if rep == nil {
		return fmt.Errorf("keycloak: identity provider %s not found", spec.Alias)
	}
	cfg, _ := rep["config"].(map[string]any)
	if cfg == nil {
		cfg = map[string]any{}
	}
	for key, val := range idpConfig(spec, "") {
		cfg[key] = val
	}
	if spec.ClientSecret != "" {
		cfg["clientSecret"] = spec.ClientSecret
	}
	rep["config"] = cfg
	rep["enabled"] = true
	rep["trustEmail"] = true
	rep["hideOnLogin"] = true
	put, err := k.do(ctx, http.MethodPut, "/identity-provider/instances/"+spec.Alias, rep)
	if err != nil {
		return err
	}
	defer func() { _ = put.Body.Close() }()
	if put.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(put.Body)
		return fmt.Errorf("keycloak: update identity provider: status %d: %s", put.StatusCode, b)
	}
	return k.syncIdPMappers(ctx, spec)
}

// idpConfig renders the OIDC IdP config; secret is included only when set
// (create or rotation).
func idpConfig(spec BrokerIdPSpec, secret string) map[string]string {
	cfg := map[string]string{
		"clientId":             spec.ClientID,
		"issuer":               spec.IssuerURL,
		"useDiscoveryEndpoint": "true",
		// Home-IdP discovery: redirect to this IdP when the entered email
		// domain matches one of the linked organization's domains.
		"kc.org.broker.redirect.mode.email-matches": "true",
	}
	if secret != "" {
		cfg["clientSecret"] = secret
	}
	return cfg
}

func (k *KeycloakAdmin) getIdPRep(ctx context.Context, alias string) (map[string]any, error) {
	resp, err := k.do(ctx, http.MethodGet, "/identity-provider/instances/"+alias, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: get identity provider: status %d", resp.StatusCode)
	}
	var rep map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return nil, err
	}
	return rep, nil
}

// syncIdPMappers replaces only the broker- owned mappers (hardcoded org
// members group, advanced claim-to-group, email attribute importer); any
// other mappers on the IdP are preserved.
func (k *KeycloakAdmin) syncIdPMappers(ctx context.Context, spec BrokerIdPSpec) error {
	base := "/identity-provider/instances/" + spec.Alias + "/mappers"
	resp, err := k.do(ctx, http.MethodGet, base, nil)
	if err != nil {
		return err
	}
	var existing []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&existing); err != nil {
		_ = resp.Body.Close()
		return err
	}
	_ = resp.Body.Close()
	for _, m := range existing {
		if !strings.HasPrefix(m.Name, "broker-") {
			continue
		}
		del, err := k.do(ctx, http.MethodDelete, base+"/"+m.ID, nil)
		if err != nil {
			return err
		}
		_ = del.Body.Close()
		if del.StatusCode != http.StatusNoContent && del.StatusCode != http.StatusNotFound {
			return fmt.Errorf("keycloak: delete idp mapper %s: status %d", m.Name, del.StatusCode)
		}
	}
	mappers := []map[string]any{{
		"name":                   "broker-org-members",
		"identityProviderAlias":  spec.Alias,
		"identityProviderMapper": "oidc-hardcoded-group-idp-mapper",
		"config": map[string]string{
			"group":    spec.OrgGroupPath,
			"syncMode": "INHERIT",
		},
	}}
	if spec.GroupsClaim != "" {
		mappers = append(mappers, map[string]any{
			"name":                   "broker-groups-" + spec.GroupsClaim,
			"identityProviderAlias":  spec.Alias,
			"identityProviderMapper": "oidc-advanced-group-idp-mapper",
			"config": map[string]string{
				"claims":                fmt.Sprintf(`[{"key":%q,"value":".*"}]`, spec.GroupsClaim),
				"are.claim.value.regex": "true",
				"group":                 spec.OrgGroupPath,
				"syncMode":              "INHERIT",
			},
		})
	}
	if spec.EmailClaim != "" {
		mappers = append(mappers, map[string]any{
			"name":                   "broker-email",
			"identityProviderAlias":  spec.Alias,
			"identityProviderMapper": "oidc-user-attribute-idp-mapper",
			"config": map[string]string{
				"claim":          spec.EmailClaim,
				"user.attribute": "email",
				"syncMode":       "INHERIT",
			},
		})
	}
	for _, m := range mappers {
		create, err := k.do(ctx, http.MethodPost, base, m)
		if err != nil {
			return err
		}
		_ = create.Body.Close()
		if create.StatusCode != http.StatusCreated && create.StatusCode != http.StatusConflict {
			return fmt.Errorf("keycloak: create idp mapper %s: status %d", m["name"], create.StatusCode)
		}
	}
	return nil
}

// LinkIdPToOrg associates the IdP with the organization (two-call write
// model, part 2). The body is a plain JSON string of the alias; 409
// (already linked) is idempotent success.
func (k *KeycloakAdmin) LinkIdPToOrg(ctx context.Context, kcOrgID, alias string) error {
	resp, err := k.do(ctx, http.MethodPost, "/organizations/"+kcOrgID+"/identity-providers", alias)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	switch resp.StatusCode {
	case http.StatusCreated, http.StatusNoContent, http.StatusConflict:
		return nil
	default:
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak: link identity provider: status %d: %s", resp.StatusCode, b)
	}
}

// UnlinkIdPFromOrg removes the org association. Unlinked IdPs have their
// org-group mappings skipped at runtime, so deletion always unlinks first.
func (k *KeycloakAdmin) UnlinkIdPFromOrg(ctx context.Context, kcOrgID, alias string) error {
	resp, err := k.do(ctx, http.MethodDelete, "/organizations/"+kcOrgID+"/identity-providers/"+alias, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("keycloak: unlink identity provider: status %d", resp.StatusCode)
	}
	return nil
}

// DeleteIdP removes the IdP instance. Callers must unlink the org first.
func (k *KeycloakAdmin) DeleteIdP(ctx context.Context, alias string) error {
	resp, err := k.do(ctx, http.MethodDelete, "/identity-provider/instances/"+alias, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("keycloak: delete identity provider: status %d", resp.StatusCode)
	}
	return nil
}

// SetOrgDomains replaces the organization's email domains (used for
// home-IdP discovery). The <slug>.inari.local placeholder is kept so the
// KC 26 at-least-one-domain requirement always holds. A Keycloak 400
// (realm-wide domain uniqueness) is surfaced as ErrDomainTaken.
func (k *KeycloakAdmin) SetOrgDomains(ctx context.Context, kcOrgID string, domains []string) error {
	resp, err := k.do(ctx, http.MethodGet, "/organizations/"+kcOrgID, nil)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return fmt.Errorf("keycloak: get organization: status %d", resp.StatusCode)
	}
	var rep map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		_ = resp.Body.Close()
		return err
	}
	_ = resp.Body.Close()
	reps := make([]map[string]any, 0, len(domains))
	for _, d := range domains {
		reps = append(reps, map[string]any{"name": d, "verified": false})
	}
	rep["domains"] = reps
	put, err := k.do(ctx, http.MethodPut, "/organizations/"+kcOrgID, rep)
	if err != nil {
		return err
	}
	defer func() { _ = put.Body.Close() }()
	if put.StatusCode == http.StatusBadRequest {
		return ErrDomainTaken
	}
	if put.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak: set org domains: status %d", put.StatusCode)
	}
	return nil
}
