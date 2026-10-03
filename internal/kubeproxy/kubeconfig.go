package kubeproxy

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kubeconfig render modes.
const (
	ModeGateway = "gateway"
	ModeDirect  = "direct"
)

// Grant types understood by kubelogin (int128/kubelogin get-token).
const (
	GrantTypeDeviceCode = "device-code"
	GrantTypeAuthCode   = "authcode"
)

// KubeconfigOptions parametrize RenderKubeconfig.
type KubeconfigOptions struct {
	// Name is the cluster/context/user name stem (e.g. "<tenant>-<cluster>").
	Name string
	// ServerURL is the apiserver endpoint the kubeconfig points at: the
	// kubeproxy /proxy URL in gateway mode, the direct apiserver URL in
	// direct mode.
	ServerURL string
	// IssuerURL is the Keycloak realm issuer; ClientID the per-tenant
	// kubelogin client (org-<slug>-kubectl).
	IssuerURL string
	ClientID  string
	// GrantType selects kubelogin's login flow (device-code default).
	GrantType string
}

// RenderKubeconfig renders the canonical secret-free exec-credential
// kubeconfig (plan §7.2): no tokens, no CA material — kubelogin mints
// short-lived tokens lazily per kubectl call. Used by the inari-server
// /kubeconfig endpoint (UI download) and kept as the single renderer the
// CLI mirrors.
func RenderKubeconfig(o KubeconfigOptions) (string, error) {
	if o.Name == "" || o.ServerURL == "" || o.IssuerURL == "" || o.ClientID == "" {
		return "", fmt.Errorf("kubeproxy: kubeconfig requires name, server URL, issuer URL and client ID")
	}
	grant := o.GrantType
	if grant == "" {
		grant = GrantTypeDeviceCode
	}
	if grant != GrantTypeDeviceCode && grant != GrantTypeAuthCode {
		return "", fmt.Errorf("kubeproxy: unsupported grant type %q", o.GrantType)
	}
	userName := o.Name + "-oidc"
	cfg := kubeconfig{
		APIVersion:     "v1",
		Kind:           "Config",
		CurrentContext: o.Name,
		Clusters: []namedCluster{{
			Name:    o.Name,
			Cluster: clusterEntry{Server: o.ServerURL},
		}},
		Contexts: []namedContext{{
			Name:    o.Name,
			Context: contextEntry{Cluster: o.Name, User: userName},
		}},
		Users: []namedUser{{
			Name: userName,
			User: userEntry{Exec: execConfig{
				APIVersion: "client.authentication.k8s.io/v1beta1",
				Command:    "kubelogin",
				Args: []string{
					"get-token",
					"--oidc-issuer-url", o.IssuerURL,
					"--oidc-client-id", o.ClientID,
					"--oidc-extra-scope", "organization",
					"--grant-type", grant,
				},
			}},
		}},
	}
	raw, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// ProxyURL builds the kubeproxy gateway URL a gateway-mode kubeconfig
// points at: <publicURL>/api/v1/tenants/<org>/clusters/<id>/proxy.
func ProxyURL(publicURL, org, clusterID string) string {
	return strings.TrimRight(publicURL, "/") +
		"/api/v1/tenants/" + org + "/clusters/" + clusterID + "/proxy"
}

// Minimal kubeconfig document model (avoids a k8s.io/client-go dependency
// for one static document shape).
type kubeconfig struct {
	APIVersion     string         `yaml:"apiVersion"`
	Kind           string         `yaml:"kind"`
	CurrentContext string         `yaml:"current-context"`
	Clusters       []namedCluster `yaml:"clusters"`
	Contexts       []namedContext `yaml:"contexts"`
	Users          []namedUser    `yaml:"users"`
}

type namedCluster struct {
	Name    string      `yaml:"name"`
	Cluster clusterEntry `yaml:"cluster"`
}

type clusterEntry struct {
	Server string `yaml:"server"`
}

type namedContext struct {
	Name    string       `yaml:"name"`
	Context contextEntry `yaml:"context"`
}

type contextEntry struct {
	Cluster string `yaml:"cluster"`
	User    string `yaml:"user"`
}

type namedUser struct {
	Name string    `yaml:"name"`
	User userEntry `yaml:"user"`
}

type userEntry struct {
	Exec execConfig `yaml:"exec"`
}

type execConfig struct {
	APIVersion string   `yaml:"apiVersion"`
	Command    string   `yaml:"command"`
	Args       []string `yaml:"args"`
}
