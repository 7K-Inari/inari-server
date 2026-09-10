package tenancy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/7K-Inari/inari-server/internal/types"
)

// KeycloakAdmin implements IdentityProvider against the Keycloak Admin REST
// API (KC 26.x), incl. the Organizations endpoints.
type KeycloakAdmin struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string
	http         *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewKeycloakAdmin(baseURL, realm, clientID, clientSecret string) *KeycloakAdmin {
	return &KeycloakAdmin{
		baseURL:      strings.TrimRight(baseURL, "/"),
		realm:        realm,
		clientID:     clientID,
		clientSecret: clientSecret,
		http:         &http.Client{Timeout: 15 * time.Second},
	}
}

func (k *KeycloakAdmin) adminToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.expiry.Add(-10*time.Second)) {
		return k.token, nil
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {k.clientID},
		"client_secret": {k.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		k.baseURL+"/realms/"+k.realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := k.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak: token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: token: status %d", resp.StatusCode)
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	k.token = body.AccessToken
	k.expiry = time.Now().Add(time.Duration(body.ExpiresIn) * time.Second)
	return k.token, nil
}

func (k *KeycloakAdmin) do(ctx context.Context, method, path string, body any) (*http.Response, error) {
	token, err := k.adminToken(ctx)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		rdr = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, k.baseURL+"/admin/realms/"+k.realm+path, rdr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return k.http.Do(req)
}

func (k *KeycloakAdmin) CreateOrganization(ctx context.Context, alias, displayName string) (string, error) {
	resp, err := k.do(ctx, http.MethodPost, "/organizations", map[string]any{
		"name":        alias,
		"alias":       alias,
		"description": displayName,
		"enabled":     true,
		// Keycloak 26 requires at least one domain per organization; default
		// to a placeholder under inari.local until real IdP domains are set.
		"domains": []map[string]any{{"name": alias + ".inari.local", "verified": false}},
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak: create organization: status %d: %s", resp.StatusCode, b)
	}
	// Location header carries the new org id.
	loc := resp.Header.Get("Location")
	id := loc[strings.LastIndex(loc, "/")+1:]
	if id == "" {
		return "", fmt.Errorf("keycloak: create organization: no id in Location header")
	}
	return id, nil
}

func (k *KeycloakAdmin) DeleteOrganization(ctx context.Context, kcOrgID string) error {
	resp, err := k.do(ctx, http.MethodDelete, "/organizations/"+kcOrgID, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("keycloak: delete organization: status %d", resp.StatusCode)
	}
	return nil
}

// UpdateOrganization updates the org profile (display name is carried in the
// KC description field, mirroring CreateOrganization). KC 26 PUT requires
// the full representation, so the org is read-modify-written.
func (k *KeycloakAdmin) UpdateOrganization(ctx context.Context, kcOrgID, displayName string) error {
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
	rep["description"] = displayName
	put, err := k.do(ctx, http.MethodPut, "/organizations/"+kcOrgID, rep)
	if err != nil {
		return err
	}
	defer func() { _ = put.Body.Close() }()
	if put.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak: update organization: status %d", put.StatusCode)
	}
	return nil
}

// CreateGroup creates nested groups along the path a/b/c.
func (k *KeycloakAdmin) CreateGroup(ctx context.Context, path string) (string, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	parentID := ""
	currentID := ""
	for _, name := range parts {
		var endpoint string
		if parentID == "" {
			endpoint = "/groups"
		} else {
			endpoint = "/groups/" + parentID + "/children"
		}
		resp, err := k.do(ctx, http.MethodPost, endpoint, map[string]any{"name": name})
		if err != nil {
			return "", err
		}
		if resp.StatusCode == http.StatusConflict {
			_ = resp.Body.Close()
			// Group exists; resolve its id and descend.
			id, err := k.findChildGroup(ctx, parentID, name)
			if err != nil {
				return "", err
			}
			parentID, currentID = id, id
			continue
		}
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			return "", fmt.Errorf("keycloak: create group %s: status %d: %s", name, resp.StatusCode, b)
		}
		loc := resp.Header.Get("Location")
		_ = resp.Body.Close()
		parentID = loc[strings.LastIndex(loc, "/")+1:]
		currentID = parentID
	}
	return currentID, nil
}

func (k *KeycloakAdmin) findChildGroup(ctx context.Context, parentID, name string) (string, error) {
	endpoint := "/groups?exact=true&search=" + url.QueryEscape(name)
	if parentID != "" {
		endpoint = "/groups/" + parentID + "/children"
	}
	resp, err := k.do(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: search group: status %d", resp.StatusCode)
	}
	var groups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&groups); err != nil {
		return "", err
	}
	for _, g := range groups {
		if g.Name == name {
			return g.ID, nil
		}
	}
	return "", fmt.Errorf("keycloak: group %q not found after conflict", name)
}

func (k *KeycloakAdmin) ListOrganizations(ctx context.Context, userID string) ([]string, error) {
	// member=true filters orgs the user belongs to.
	q := url.Values{"member": {userID}}
	resp, err := k.do(ctx, http.MethodGet, "/organizations?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: list organizations: status %d", resp.StatusCode)
	}
	var orgs []struct {
		Alias string `json:"alias"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&orgs); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, o.Alias)
	}
	return out, nil
}

// CreateClusterClient provisions the per-cluster OIDC client cluster-<id>:
// confidential, client-credentials grant only, with a hardcoded cluster_id
// claim mapper so the agent's identity always comes from the token, never
// self-asserted (plan §5.3, §5.10). Returns the clientID.
func (k *KeycloakAdmin) CreateClusterClient(ctx context.Context, clusterID string) (string, error) {
	clientID := "cluster-" + clusterID
	resp, err := k.do(ctx, http.MethodPost, "/clients", map[string]any{
		"clientId":                  clientID,
		"enabled":                   true,
		"publicClient":              false,
		"standardFlowEnabled":       false,
		"serviceAccountsEnabled":    true,
		"directAccessGrantsEnabled": false,
		"protocolMappers": []map[string]any{{
			"name":           "cluster_id",
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-hardcoded-claim-mapper",
			"config": map[string]string{
				"claim.name":                 "cluster_id",
				"claim.value":                clusterID,
				"jsonType.label":             "String",
				"access.token.claim":         "true",
				"id.token.claim":             "true",
				"userinfo.token.claim":       "false",
				"access.tokenResponse.claim": "false",
			},
		}, {
			// The server's JWT verifier requires aud=inari-server; without this
			// mapper the agent's client-credentials token is rejected at the
			// EventStream handshake.
			"name":           "audience-inari-server",
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{
				"included.client.audience": "inari-server",
				"id.token.claim":           "false",
				"access.token.claim":       "true",
				"userinfo.token.claim":     "false",
			},
		}},
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusConflict {
		// Idempotent: client already exists for this cluster id.
		return clientID, nil
	}
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak: create client: status %d: %s", resp.StatusCode, b)
	}
	return clientID, nil
}

// ClusterClientSecret reads the generated secret of a confidential client
// via the admin API so the registration exchange can hand it to the platform
// secret store (ESO delivery, plan §5.3). The value never transits the
// agent-facing API.
func (k *KeycloakAdmin) ClusterClientSecret(ctx context.Context, clientID string) (string, error) {
	uuid, err := k.findClientUUID(ctx, clientID)
	if err != nil {
		return "", err
	}
	if uuid == "" {
		return "", fmt.Errorf("keycloak: client %s not found", clientID)
	}
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+uuid+"/client-secret", nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: client secret: status %d", resp.StatusCode)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Value == "" {
		return "", fmt.Errorf("keycloak: client %s has empty secret", clientID)
	}
	return body.Value, nil
}

// Identity client types for the generic OIDC client CRUD (Settings design
// §3.1). Secrets live only in Keycloak and are returned once at create/rotate.
const (
	ClientTypeService = "service"
	ClientTypePublic  = "public"
)

// ClientSpec describes a tenant-scoped OIDC client (clientId
// org-<org>-<name>) managed via the Admin API.
type ClientSpec struct {
	ClientID     string
	Name         string
	ClientType   string
	Audiences    []string
	Scopes       []string
	RedirectURIs []string
	Enabled      bool
}

// CreateClient provisions a tenant OIDC client in the inari realm and, for
// confidential (service) clients, returns the generated secret exactly once.
// Public clients have no secret. Scopes are attached as optional client
// scopes (realm client scopes are created on demand).
func (k *KeycloakAdmin) CreateClient(ctx context.Context, spec ClientSpec) (string, error) {
	public := spec.ClientType == ClientTypePublic
	rep := map[string]any{
		"clientId":                  spec.ClientID,
		"name":                      spec.Name,
		"enabled":                   true,
		"publicClient":              public,
		"standardFlowEnabled":       public,
		"serviceAccountsEnabled":    !public,
		"directAccessGrantsEnabled": false,
		"redirectUris":              spec.RedirectURIs,
		"protocolMappers":           audienceMappers(spec.Audiences),
	}
	resp, err := k.do(ctx, http.MethodPost, "/clients", rep)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusConflict {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak: create client: status %d: %s", resp.StatusCode, b)
	}
	if err := k.syncOptionalScopes(ctx, spec.ClientID, spec.Scopes); err != nil {
		return "", err
	}
	if public {
		return "", nil
	}
	return k.readClientSecret(ctx, spec.ClientID)
}

// GetClient returns the spec of a managed client, or nil when it does not
// exist in the realm.
func (k *KeycloakAdmin) GetClient(ctx context.Context, clientID string) (*ClientSpec, error) {
	uuid, err := k.findClientUUID(ctx, clientID)
	if err != nil {
		return nil, err
	}
	if uuid == "" {
		return nil, nil
	}
	rep, err := k.getClientRep(ctx, uuid)
	if err != nil {
		return nil, err
	}
	spec := &ClientSpec{
		ClientID:   clientID,
		Name:       stringField(rep, "name"),
		Enabled:    boolField(rep, "enabled"),
		Scopes:     stringSliceField(rep, "optionalClientScopes"),
		ClientType: ClientTypeService,
	}
	if boolField(rep, "publicClient") {
		spec.ClientType = ClientTypePublic
	}
	spec.RedirectURIs = stringSliceField(rep, "redirectUris")
	if mappers, ok := rep["protocolMappers"].([]any); ok {
		for _, m := range mappers {
			mm, _ := m.(map[string]any)
			if mm["protocolMapper"] != "oidc-audience-mapper" {
				continue
			}
			if cfg, ok := mm["config"].(map[string]any); ok {
				spec.Audiences = append(spec.Audiences, fmt.Sprint(cfg["included.client.audience"]))
			}
		}
	}
	return spec, nil
}

// UpdateClient applies a full read-modify-write of the client
// representation: display name, enabled flag, redirect URIs, managed audience
// mappers, and optional client scopes.
func (k *KeycloakAdmin) UpdateClient(ctx context.Context, spec ClientSpec) error {
	uuid, err := k.findClientUUID(ctx, spec.ClientID)
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf("keycloak: client %s not found", spec.ClientID)
	}
	rep, err := k.getClientRep(ctx, uuid)
	if err != nil {
		return err
	}
	rep["name"] = spec.Name
	rep["enabled"] = spec.Enabled
	rep["redirectUris"] = spec.RedirectURIs
	// Replace only the audience mappers we manage (name prefix audience-);
	// any other mappers on the client are preserved.
	var kept []any
	if mappers, ok := rep["protocolMappers"].([]any); ok {
		for _, m := range mappers {
			mm, _ := m.(map[string]any)
			if name, _ := mm["name"].(string); strings.HasPrefix(name, "audience-") {
				continue
			}
			kept = append(kept, m)
		}
	}
	for _, m := range audienceMappers(spec.Audiences) {
		kept = append(kept, m)
	}
	rep["protocolMappers"] = kept
	put, err := k.do(ctx, http.MethodPut, "/clients/"+uuid, rep)
	if err != nil {
		return err
	}
	defer func() { _ = put.Body.Close() }()
	if put.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak: update client: status %d", put.StatusCode)
	}
	return k.syncOptionalScopes(ctx, spec.ClientID, spec.Scopes)
}

// RotateClientSecret regenerates the confidential client's secret in
// Keycloak and returns the new value exactly once (recovery path, Settings
// design §3.1).
func (k *KeycloakAdmin) RotateClientSecret(ctx context.Context, clientID string) (string, error) {
	uuid, err := k.findClientUUID(ctx, clientID)
	if err != nil {
		return "", err
	}
	if uuid == "" {
		return "", fmt.Errorf("keycloak: client %s not found", clientID)
	}
	resp, err := k.do(ctx, http.MethodPost, "/clients/"+uuid+"/client-secret", nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: rotate client secret: status %d", resp.StatusCode)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Value == "" {
		return "", fmt.Errorf("keycloak: client %s rotated to empty secret", clientID)
	}
	return body.Value, nil
}

// audienceMappers renders one oidc-audience-mapper per audience (same shape
// as the cluster client's inari-server mapper).
func audienceMappers(audiences []string) []map[string]any {
	mappers := make([]map[string]any, 0, len(audiences))
	for _, aud := range audiences {
		mappers = append(mappers, map[string]any{
			"name":           "audience-" + aud,
			"protocol":       "openid-connect",
			"protocolMapper": "oidc-audience-mapper",
			"config": map[string]string{
				"included.client.audience": aud,
				"id.token.claim":           "false",
				"access.token.claim":       "true",
				"userinfo.token.claim":     "false",
			},
		})
	}
	return mappers
}

// syncOptionalScopes ensures each scope exists as a realm client scope and
// links it to the client as an optional client scope.
func (k *KeycloakAdmin) syncOptionalScopes(ctx context.Context, clientID string, scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}
	uuid, err := k.findClientUUID(ctx, clientID)
	if err != nil {
		return err
	}
	if uuid == "" {
		return fmt.Errorf("keycloak: client %s not found", clientID)
	}
	for _, scope := range scopes {
		scopeUUID, err := k.ensureClientScope(ctx, scope)
		if err != nil {
			return err
		}
		resp, err := k.do(ctx, http.MethodPut, "/clients/"+uuid+"/optional-client-scopes/"+scopeUUID, nil)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			return fmt.Errorf("keycloak: link optional scope %s: status %d", scope, resp.StatusCode)
		}
	}
	return nil
}

// ensureClientScope returns the id of the realm client scope with the given
// name, creating it when missing.
func (k *KeycloakAdmin) ensureClientScope(ctx context.Context, name string) (string, error) {
	resp, err := k.do(ctx, http.MethodGet, "/client-scopes", nil)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return "", fmt.Errorf("keycloak: list client scopes: status %d", resp.StatusCode)
	}
	var scopes []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&scopes); err != nil {
		_ = resp.Body.Close()
		return "", err
	}
	_ = resp.Body.Close()
	for _, s := range scopes {
		if s.Name == name {
			return s.ID, nil
		}
	}
	create, err := k.do(ctx, http.MethodPost, "/client-scopes", map[string]any{
		"name":     name,
		"protocol": "openid-connect",
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = create.Body.Close() }()
	if create.StatusCode == http.StatusConflict {
		return "", fmt.Errorf("keycloak: client scope %s listed absent but create conflicted", name)
	}
	if create.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(create.Body)
		return "", fmt.Errorf("keycloak: create client scope %s: status %d: %s", name, create.StatusCode, b)
	}
	loc := create.Header.Get("Location")
	return loc[strings.LastIndex(loc, "/")+1:], nil
}

// readClientSecret reads the generated secret of a confidential client once
// (create/rotate responses only; never persisted server-side).
func (k *KeycloakAdmin) readClientSecret(ctx context.Context, clientID string) (string, error) {
	uuid, err := k.findClientUUID(ctx, clientID)
	if err != nil {
		return "", err
	}
	if uuid == "" {
		return "", fmt.Errorf("keycloak: client %s not found", clientID)
	}
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+uuid+"/client-secret", nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: client secret: status %d", resp.StatusCode)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", err
	}
	if body.Value == "" {
		return "", fmt.Errorf("keycloak: client %s has empty secret", clientID)
	}
	return body.Value, nil
}

func (k *KeycloakAdmin) getClientRep(ctx context.Context, uuid string) (map[string]any, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+uuid, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: get client: status %d", resp.StatusCode)
	}
	var rep map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return nil, err
	}
	return rep, nil
}

func stringField(rep map[string]any, key string) string {
	s, _ := rep[key].(string)
	return s
}

func boolField(rep map[string]any, key string) bool {
	b, _ := rep[key].(bool)
	return b
}

func stringSliceField(rep map[string]any, key string) []string {
	var out []string
	if items, ok := rep[key].([]any); ok {
		for _, it := range items {
			if s, ok := it.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// DisableClient revokes a cluster's identity by disabling its client (plan
// §5.3 revocation path); in-flight tokens expire on their short TTL.
func (k *KeycloakAdmin) DisableClient(ctx context.Context, clientID string) error {
	uuid, err := k.findClientUUID(ctx, clientID)
	if err != nil {
		return err
	}
	if uuid == "" {
		return nil // already gone
	}
	resp, err := k.do(ctx, http.MethodGet, "/clients/"+uuid, nil)
	if err != nil {
		return err
	}
	var rep map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		_ = resp.Body.Close()
		return err
	}
	_ = resp.Body.Close()
	rep["enabled"] = false
	put, err := k.do(ctx, http.MethodPut, "/clients/"+uuid, rep)
	if err != nil {
		return err
	}
	defer func() { _ = put.Body.Close() }()
	if put.StatusCode != http.StatusNoContent {
		return fmt.Errorf("keycloak: disable client: status %d", put.StatusCode)
	}
	return nil
}

func (k *KeycloakAdmin) findClientUUID(ctx context.Context, clientID string) (string, error) {
	resp, err := k.do(ctx, http.MethodGet, "/clients?clientId="+url.QueryEscape(clientID), nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keycloak: find client: status %d", resp.StatusCode)
	}
	var clients []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&clients); err != nil {
		return "", err
	}
	if len(clients) == 0 {
		return "", nil
	}
	return clients[0].ID, nil
}

// AddOrganizationMember adds a user to a Keycloak Organization (drives the
// organization token claim). Idempotent: 409 means already a member.
func (k *KeycloakAdmin) AddOrganizationMember(ctx context.Context, kcOrgID, userID string) error {
	resp, err := k.do(ctx, http.MethodPost, "/organizations/"+kcOrgID+"/members", userID)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusConflict {
		return nil
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak: add org member: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (k *KeycloakAdmin) RemoveOrganizationMember(ctx context.Context, kcOrgID, userID string) error {
	resp, err := k.do(ctx, http.MethodDelete, "/organizations/"+kcOrgID+"/members/"+userID, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("keycloak: remove org member: status %d", resp.StatusCode)
	}
	return nil
}

// AddGroupMember joins a user to the group at path a/b/c.
func (k *KeycloakAdmin) AddGroupMember(ctx context.Context, groupPath, userID string) error {
	gid, err := k.resolveGroupID(ctx, groupPath)
	if err != nil {
		return err
	}
	resp, err := k.do(ctx, http.MethodPut, "/users/"+userID+"/groups/"+gid, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("keycloak: add group member: status %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (k *KeycloakAdmin) RemoveGroupMember(ctx context.Context, groupPath, userID string) error {
	gid, err := k.resolveGroupID(ctx, groupPath)
	if err != nil {
		return err
	}
	resp, err := k.do(ctx, http.MethodDelete, "/users/"+userID+"/groups/"+gid, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("keycloak: remove group member: status %d", resp.StatusCode)
	}
	return nil
}

// DeleteGroup removes the group at path a/b/c. Idempotent: an unresolvable
// path means the group is already gone.
func (k *KeycloakAdmin) DeleteGroup(ctx context.Context, groupPath string) error {
	gid, err := k.resolveGroupID(ctx, groupPath)
	if err != nil {
		// Resolution failure means the path (or a parent) is gone already.
		return nil
	}
	resp, err := k.do(ctx, http.MethodDelete, "/groups/"+gid, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return fmt.Errorf("keycloak: delete group: status %d", resp.StatusCode)
	}
	return nil
}

// ListGroupMembers returns the Keycloak user ids of the group at path a/b/c.
func (k *KeycloakAdmin) ListGroupMembers(ctx context.Context, groupPath string) ([]string, error) {
	gid, err := k.resolveGroupID(ctx, groupPath)
	if err != nil {
		return nil, err
	}
	// Dev-scale: a single page is plenty; paginate when the group outgrows it.
	resp, err := k.do(ctx, http.MethodGet, "/groups/"+gid+"/members?max=500", nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: list group members: status %d", resp.StatusCode)
	}
	var users []struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&users); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.ID)
	}
	return out, nil
}

// resolveGroupID walks a/b/c one level at a time to the leaf group id.
func (k *KeycloakAdmin) resolveGroupID(ctx context.Context, path string) (string, error) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	parentID := ""
	id := ""
	for _, name := range parts {
		var err error
		id, err = k.findChildGroup(ctx, parentID, name)
		if err != nil {
			return "", fmt.Errorf("keycloak: resolve group %s: %w", path, err)
		}
		parentID = id
	}
	return id, nil
}

// GetUser validates a subject exists and returns its profile.
func (k *KeycloakAdmin) GetUser(ctx context.Context, userID string) (*types.User, error) {
	resp, err := k.do(ctx, http.MethodGet, "/users/"+userID, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrUserNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak: get user: status %d", resp.StatusCode)
	}
	var rep struct {
		ID        string `json:"id"`
		Email     string `json:"email"`
		FirstName string `json:"firstName"`
		LastName  string `json:"lastName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		return nil, err
	}
	return &types.User{
		ID:          rep.ID,
		Email:       rep.Email,
		DisplayName: strings.TrimSpace(rep.FirstName + " " + rep.LastName),
	}, nil
}
