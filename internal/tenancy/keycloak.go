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
