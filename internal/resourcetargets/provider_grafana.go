package resourcetargets

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/7K-Inari/inari-server/internal/types"
)

type grafanaDatasource struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type grafanaEvidence struct {
	AddonID string `json:"addonId"`
}

type grafanaConfig struct {
	BaseURL        string              `json:"baseUrl"`
	Evaluation     string              `json:"evaluation"`
	FolderPrefixes []string            `json:"folderPrefixes"`
	Datasources    []grafanaDatasource `json:"datasources"`
	Approval       ApprovalPolicy      `json:"approval"`
	Evidence       grafanaEvidence     `json:"evidence"`
}

type grafanaSelection struct {
	Folder     string `json:"folder"`
	Datasource string `json:"datasource"`
	Evaluation string `json:"evaluation"`
}

type grafanaProvider struct{}

func (grafanaProvider) Describe() ProviderDescriptor {
	return ProviderDescriptor{
		Capability: CapabilityMonitoringGrafana, ResourceKinds: []string{ResourceKindCluster},
		Actions: []Action{ActionView, ActionProvision},
		ConfigSchema: json.RawMessage(`{
			"type":"object","additionalProperties":false,
			"required":["baseUrl","evaluation","folderPrefixes","datasources","approval","evidence"],
			"properties":{
				"baseUrl":{"type":"string","format":"uri","pattern":"^https://"},
				"evaluation":{"type":"string","enum":["central","local"]},
				"folderPrefixes":{"type":"array","minItems":1,"items":{"type":"string","minLength":1}},
				"datasources":{"type":"array","minItems":1,"items":{"type":"object","additionalProperties":false,"required":["name","type"],"properties":{"name":{"type":"string"},"type":{"type":"string"}}}},
				"approval":{"type":"object","additionalProperties":false,"properties":{"required":{"type":"boolean"},"approverTeamIds":{"type":"array","items":{"type":"string"}}}},
				"evidence":{"type":"object","additionalProperties":false,"required":["addonId"],"properties":{"addonId":{"type":"string"}}
			}
		}`),
		SelectionSchema: json.RawMessage(`{"type":"object","additionalProperties":false,"required":["folder","datasource","evaluation"],"properties":{"folder":{"type":"string"},"datasource":{"type":"string"},"evaluation":{"type":"string","enum":["central","local"]}}}`),
		UISchema:        json.RawMessage(`{"picker":"grafana","fields":["folder","datasource"],"approval":"policy"}`),
		SupportsDefault: true,
	}
}

func parseGrafanaConfig(raw json.RawMessage) (grafanaConfig, error) {
	var cfg grafanaConfig
	if err := decodeStrict(raw, &cfg); err != nil {
		return cfg, err
	}
	if cfg.BaseURL == "" {
		return cfg, invalid("config.baseUrl", "baseUrl is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return cfg, invalid("config.baseUrl", "must be an absolute https URL without userinfo, query, or fragment")
	}
	cfg.BaseURL = strings.TrimRight(u.String(), "/")
	if cfg.Evaluation != "central" && cfg.Evaluation != "local" {
		return cfg, invalid("config.evaluation", "must be central or local")
	}
	if len(cfg.FolderPrefixes) == 0 {
		return cfg, invalid("config.folderPrefixes", "at least one folder prefix is required")
	}
	for i, prefix := range cfg.FolderPrefixes {
		if strings.TrimSpace(prefix) == "" || prefix != strings.TrimSpace(prefix) || strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") {
			return cfg, invalid(fmt.Sprintf("config.folderPrefixes.%d", i), "folder prefix must be a trimmed relative path")
		}
		for _, segment := range strings.Split(prefix, "/") {
			if segment == "" || segment == "." || segment == ".." {
				return cfg, invalid(fmt.Sprintf("config.folderPrefixes.%d", i), "folder prefix contains an invalid segment")
			}
		}
	}
	if len(cfg.Datasources) == 0 {
		return cfg, invalid("config.datasources", "at least one datasource is required")
	}
	seen := map[string]bool{}
	for i, ds := range cfg.Datasources {
		if strings.TrimSpace(ds.Name) == "" || strings.TrimSpace(ds.Type) == "" {
			return cfg, invalid(fmt.Sprintf("config.datasources.%d", i), "datasource name and type are required")
		}
		if seen[ds.Name] {
			return cfg, invalid(fmt.Sprintf("config.datasources.%d", i), "datasource names must be unique")
		}
		seen[ds.Name] = true
	}
	if cfg.Approval.Required && len(cfg.Approval.ApproverTeamIDs) == 0 {
		return cfg, invalid("config.approval.approverTeamIds", "required approval needs at least one approver team")
	}
	if cfg.Evidence.AddonID == "" {
		return cfg, invalid("config.evidence.addonId", "addonId is required")
	}
	return cfg, nil
}

func (grafanaProvider) NormalizeConfig(raw json.RawMessage) (json.RawMessage, error) {
	cfg, err := parseGrafanaConfig(raw)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func validateGrafanaSnapshot(snapshot ResourceSnapshot, cfg grafanaConfig) error {
	cluster := snapshot.Cluster
	if cluster == nil {
		return invalid("resourceRef", "cluster does not exist")
	}
	if cluster.State != types.ClusterStateActive && cluster.State != types.ClusterStateDegraded {
		return invalid("resourceRef", "cluster is not active")
	}
	if snapshot.BaselineRepo == nil || snapshot.BaselineRepo.OrgID != cluster.OrgID || snapshot.BaselineRepo.Scope != types.GitRepoScopePlatform {
		return invalid("binding.baselineRepoId", "a same-org platform baseline is required")
	}
	var addon *types.ClusterAddon
	for _, candidate := range snapshot.Addons {
		if candidate.ID == cfg.Evidence.AddonID {
			addon = candidate
			break
		}
	}
	if addon == nil || addon.OrgID != cluster.OrgID || addon.ClusterID != cluster.ID {
		return invalid("config.evidence.addonId", "addon must be a concrete row on the target cluster")
	}
	var release struct {
		ReleaseName string `json:"releaseName"`
		Namespace   string `json:"namespace"`
	}
	if err := decodeStrict(addon.DiscoveredMeta, &release); err != nil || release.ReleaseName == "" || release.Namespace == "" {
		return invalid("config.evidence.addonId", "addon has no discovered Helm release identity")
	}
	capabilityName := release.Namespace + "/" + release.ReleaseName
	deployed := false
	for _, capability := range snapshot.Capabilities {
		if capability.Kind != types.CapabilityKindHelmRelease || capability.Name != capabilityName || capability.Group != "helm.sh" {
			continue
		}
		var hints struct {
			Status string `json:"status"`
		}
		if err := decodeStrict(capability.UIHints, &hints); err == nil && hints.Status == "deployed" {
			deployed = true
			break
		}
	}
	if !deployed {
		return invalid("config.evidence.addonId", "matching Helm release capability is not deployed")
	}
	teams := make(map[string]bool, len(snapshot.TeamIDs))
	for _, id := range snapshot.TeamIDs {
		teams[id] = true
	}
	for _, id := range cfg.Approval.ApproverTeamIDs {
		if !teams[id] {
			return invalid("config.approval.approverTeamIds", "approver team must belong to the org")
		}
	}
	return nil
}

func (p grafanaProvider) ValidateRegistration(snapshot ResourceSnapshot, raw json.RawMessage) error {
	cfg, err := parseGrafanaConfig(raw)
	if err != nil {
		return err
	}
	return validateGrafanaSnapshot(snapshot, cfg)
}

func (p grafanaProvider) Resolve(target *Target, snapshot ResourceSnapshot) (Binding, Readiness, error) {
	cfg, err := parseGrafanaConfig(target.Config)
	if err != nil {
		return Binding{}, Readiness{}, err
	}
	binding := clusterBinding(snapshot)
	readiness := Readiness{State: ReadinessReady}
	if snapshot.Cluster != nil {
		readiness.ObservedAt = snapshot.Cluster.LastSeenAt
	}
	if snapshot.Cluster == nil || snapshot.Cluster.ID != target.ResourceRef.ID {
		readiness.State = ReadinessUnavailable
		readiness.Reasons = []string{"cluster_not_found"}
		return binding, readiness, nil
	}
	if err := validateGrafanaSnapshot(snapshot, cfg); err != nil {
		readiness.State = ReadinessUnavailable
		readiness.Reasons = []string{"grafana_evidence_or_policy_unavailable"}
		return binding, readiness, nil
	}
	if snapshot.Cluster.State == types.ClusterStateDegraded {
		readiness.State = ReadinessDegraded
		readiness.Reasons = []string{"cluster_degraded"}
	}
	return binding, readiness, nil
}

func (p grafanaProvider) ValidateSelection(target *Target, raw json.RawMessage) (json.RawMessage, ApprovalPolicy, error) {
	cfg, err := parseGrafanaConfig(target.Config)
	if err != nil {
		return nil, ApprovalPolicy{}, err
	}
	var selection grafanaSelection
	if err := decodeStrict(raw, &selection); err != nil {
		return nil, ApprovalPolicy{}, err
	}
	if selection.Evaluation != cfg.Evaluation {
		return nil, ApprovalPolicy{}, invalid("selection.evaluation", "evaluation must match target policy")
	}
	folderAllowed := false
	for _, prefix := range cfg.FolderPrefixes {
		if selection.Folder == prefix || strings.HasPrefix(selection.Folder, prefix+"/") {
			folderAllowed = true
			break
		}
	}
	if !folderAllowed {
		return nil, ApprovalPolicy{}, invalid("selection.folder", "folder is outside the target policy")
	}
	datasourceAllowed := false
	for _, ds := range cfg.Datasources {
		if ds.Name == selection.Datasource {
			datasourceAllowed = true
			break
		}
	}
	if !datasourceAllowed {
		return nil, ApprovalPolicy{}, invalid("selection.datasource", "datasource is outside the target policy")
	}
	normalized, err := json.Marshal(selection)
	if err != nil {
		return nil, ApprovalPolicy{}, err
	}
	return normalized, cfg.Approval, nil
}
