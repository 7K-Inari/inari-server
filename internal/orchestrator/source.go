package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/7K-Inari/inari-server/internal/types"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
)

// sourceDescriptor returns the exact render source and whether registration
// must use the rendered multi-source Application rather than the legacy
// single-source proto contract.
func (s *Service) sourceDescriptor(ctx context.Context, req DeployRequest, version string) (types.SourceDescriptor, bool, error) {
	row, err := s.catalog.GetVersion(ctx, req.ItemID, version)
	if err != nil {
		return types.SourceDescriptor{}, false, err
	}
	var payload struct {
		Admission struct {
			Type string `json:"type"`
		} `json:"admission"`
		Chart *struct {
			RepoURL string `json:"repoURL"`
			Chart   string `json:"chart"`
			Digest  string `json:"digest"`
		} `json:"chart"`
	}
	if len(row.Payload) == 0 {
		return types.SourceDescriptor{Kind: types.SourceKindKRO, KRO: &types.KROSource{RGDRef: rgdRef(req.ItemID, version), Instance: req.Spec}}, false, nil
	}
	if err := json.Unmarshal(row.Payload, &payload); err != nil {
		return types.SourceDescriptor{}, false, err
	}
	if payload.Chart == nil && payload.Admission.Type != "platform-app" {
		return types.SourceDescriptor{Kind: types.SourceKindKRO, KRO: &types.KROSource{RGDRef: rgdRef(req.ItemID, version), Instance: req.Spec}}, false, nil
	}
	if payload.Chart == nil || !strings.HasPrefix(payload.Chart.RepoURL, "oci://") || payload.Chart.Chart == "" || len(payload.Chart.Digest) != 71 || !strings.HasPrefix(payload.Chart.Digest, "sha256:") {
		return types.SourceDescriptor{}, false, errors.New("platform-app requires exact OCI chart coordinates and digest")
	}
	return types.SourceDescriptor{Kind: types.SourceKindHelm, Helm: &types.HelmSource{RepoURL: payload.Chart.RepoURL, Chart: payload.Chart.Chart, Version: version, Digest: payload.Chart.Digest}}, true, nil
}

func (s *Service) enqueueAppManifestRegistration(ctx context.Context, clusterID, instanceID string, manifest []byte) error {
	if len(manifest) == 0 {
		return errors.New("orchestrator: helm render produced no application manifest")
	}
	if s.queue == nil {
		return errors.New("orchestrator: agent queue is not configured")
	}
	name := "inari-" + strings.ToLower(instanceID)
	payload, err := structpb.NewStruct(map[string]any{"commandId": name, "name": name, "namespace": "argocd", "manifest": string(manifest)})
	if err != nil {
		return err
	}
	any, err := anypb.New(payload)
	if err != nil {
		return err
	}
	raw, err := protojson.Marshal(any)
	if err != nil {
		return err
	}
	return s.queue.Enqueue(ctx, &types.AgentCommand{
		ID: "register-argocd-app-manifest:" + name, ClusterID: clusterID,
		Type: "EVENT_TYPE_REGISTER_ARGOCD_APP_MANIFEST", Payload: raw,
	})
}
