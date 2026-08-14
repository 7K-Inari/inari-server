package clusterregistry

import (
	"bytes"
	"fmt"
	"strconv"
	"text/template"

	"github.com/7K-Inari/inari-server/internal/types"
)

// ManifestParams configure the rendered agent install manifest.
type ManifestParams struct {
	// AgentImageRepo/Tag reference the published agent image from the
	// inari-agent release pipeline (never a locally built tag).
	AgentImageRepo string
	AgentImageTag  string
	// GatewayAddress is the base URL agents dial out to (pull, never push).
	GatewayAddress string
}

var installManifest = template.Must(template.New("agent-install").Funcs(template.FuncMap{
	"quote": strconv.Quote,
}).Parse(`apiVersion: v1
kind: Namespace
metadata:
  name: inari-system
---
apiVersion: v1
kind: Secret
metadata:
  name: inari-agent-bootstrap
  namespace: inari-system
type: Opaque
stringData:
  registration-token: {{ .Token }}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: inari-agent
  namespace: inari-system
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: inari-agent
  namespace: inari-system
  labels:
    app.kubernetes.io/name: inari-agent
spec:
  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: inari-agent
  template:
    metadata:
      labels:
        app.kubernetes.io/name: inari-agent
    spec:
      serviceAccountName: inari-agent
      containers:
        - name: agent
          image: {{ .Image | quote }}
          imagePullPolicy: IfNotPresent
          resources:
            requests:
              cpu: 50m
              memory: 64Mi
            limits:
              cpu: 100m
              memory: 128Mi
          env:
            - name: INARI_GATEWAY_ADDRESS
              value: {{ .GatewayAddress | quote }}
            - name: INARI_CLUSTER_ID
              value: {{ .ClusterID | quote }}
            - name: INARI_REGISTRATION_TOKEN
              valueFrom:
                secretKeyRef:
                  name: inari-agent-bootstrap
                  key: registration-token
`))

// RenderInstallManifest renders the agent install manifest embedding the
// one-time registration token (plan §5.3 lifecycle step 1).
func RenderInstallManifest(cluster *types.Cluster, token string, p ManifestParams) ([]byte, error) {
	if p.AgentImageRepo == "" || p.AgentImageTag == "" {
		return nil, fmt.Errorf("clusterregistry: agent image repo/tag required")
	}
	if p.GatewayAddress == "" {
		return nil, fmt.Errorf("clusterregistry: gateway address required")
	}
	var buf bytes.Buffer
	err := installManifest.Execute(&buf, map[string]string{
		"Token":          token,
		"Image":          p.AgentImageRepo + ":" + p.AgentImageTag,
		"GatewayAddress": p.GatewayAddress,
		"ClusterID":      cluster.ID,
	})
	if err != nil {
		return nil, fmt.Errorf("clusterregistry: render manifest: %w", err)
	}
	return buf.Bytes(), nil
}
