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
	baseURL  string
	realm    string
	username string
	password string
	http     *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewKeycloakAdmin(baseURL, realm, username, password string) *KeycloakAdmin {
	return &KeycloakAdmin{
		baseURL:  strings.TrimRight(baseURL, "/"),
		realm:    realm,
		username: username,
		password: password,
		http:     &http.Client{Timeout: 15 * time.Second},
	}
}

func (k *KeycloakAdmin) adminToken(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Before(k.expiry.Add(-10*time.Second)) {
		return k.token, nil
	}
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {k.username},
		"password":   {k.password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		k.baseURL+"/realms/master/protocol/openid-connect/token", strings.NewReader(form.Encode()))
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
