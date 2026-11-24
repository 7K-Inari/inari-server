package verification

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	trustedsource "github.com/7K-Inari/inari-api/contract/trustedsource/v1"
	"github.com/7K-Inari/inari-server/internal/catalog"
	"github.com/Masterminds/semver/v3"
	"go.yaml.in/yaml/v4"
)

// ParseSuiteArtifact validates the admitted bytes and requested real profile.
func ParseSuiteArtifact(admitted *catalog.AdmittedSmokeSuite, profile string, environment trustedsource.Environment, legacyException bool, now time.Time) (*SuiteRelease, error) {
	if admitted == nil || admitted.Evidence == nil {
		return nil, errors.New("suite admission result is required")
	}
	rawSuite, ok := admitted.Evidence.Files["suite.yaml"]
	if !ok || len(rawSuite) == 0 {
		return nil, errors.New("signed suite.yaml is missing")
	}
	var suite Suite
	if err := decodeSingleYAML(rawSuite, &suite, true); err != nil {
		return nil, fmt.Errorf("decode signed suite.yaml: %w", err)
	}
	if suite.SuiteSchema != "inari.smoke.v1" {
		return nil, errors.New("suiteSchema must be inari.smoke.v1")
	}
	if suite.Target.Adapter.Kind == "" {
		suite.Target.Adapter.Kind = "helm"
	}
	if suite.Target.ID == "" || suite.Target.Version == "" {
		return nil, errors.New("suite target id/version are required")
	}
	if _, err := semver.StrictNewVersion(suite.Target.Version); err != nil {
		return nil, fmt.Errorf("suite target.version must be SemVer: %w", err)
	}
	if _, err := semver.NewConstraint(suite.CompatibleAppVersions); err != nil {
		return nil, fmt.Errorf("compatibleAppVersions: %w", err)
	}
	if admitted.Descriptor.Component != suite.Target.ID || admitted.Descriptor.PackageVersion != suite.Target.Version {
		return nil, errors.New("suite descriptor component or package version does not match target")
	}
	if admitted.Descriptor.MediaType != trustedsource.SmokeSuiteMediaType || admitted.Descriptor.Digest == "" {
		return nil, errors.New("suite descriptor must be an exact signed smoke artifact")
	}
	if suite.ParameterContract == "" || suite.Entrypoint == "" || !safeSuitePath(suite.WorkflowTemplate) {
		return nil, errors.New("parameterContract, entrypoint, and a safe workflowTemplate path are required")
	}
	workflow, ok := admitted.Evidence.Files[suite.WorkflowTemplate]
	if !ok || len(workflow) == 0 {
		return nil, errors.New("signed WorkflowTemplate file is missing")
	}
	if _, err := time.ParseDuration(suite.Timeout); err != nil {
		return nil, fmt.Errorf("suite timeout: %w", err)
	}
	if err := validateSuiteAdapter(&suite); err != nil {
		return nil, err
	}
	profileConfig, found := suite.Profiles[profile]
	if !found || profileConfig.Cleanup != "required" {
		return nil, fmt.Errorf("suite profile %q or its required cleanup declaration is missing", profile)
	}
	if profileConfig.SideEffects != SideEffectReadOnly && profileConfig.SideEffects != SideEffectSyntheticWrite && profileConfig.SideEffects != SideEffectMutating {
		return nil, fmt.Errorf("suite profile %q has invalid side effects", profile)
	}
	if len(suite.ExecutableProfiles) > 0 && !contains(suite.ExecutableProfiles, profile) {
		return nil, &trustedsource.EligibilityError{Code: trustedsource.CodeSuiteProfileNotExecutable, Reason: "profile is absent from suite executableProfiles"}
	}
	if environment == trustedsource.EnvironmentProduction && (admitted.Evidence.Unsigned || (admitted.Source.TrustTier != trustedsource.TrustOfficial && admitted.Source.TrustTier != trustedsource.TrustReviewed)) {
		return nil, errors.New("unsigned_production_denied: production requires a signed official or reviewed suite")
	}
	evidence := admitted.Evidence.TestEvidence
	legacyAllowed := legacyException && environment == trustedsource.EnvironmentDevelopment && suite.Target.Component != ""
	if evidence == nil {
		return nil, &trustedsource.EligibilityError{Code: trustedsource.CodeSuiteEligibilityUnknown, Reason: "signed test evidence is required for real-environment eligibility"}
	}
	if err := evidence.ValidateRealEnvironmentEligibility(profile, environment, legacyAllowed); err != nil {
		return nil, err
	}
	if evidence.FixtureOnly != nil && *evidence.FixtureOnly != suite.Target.Adapter.FixtureOnly {
		return nil, errors.New("signed evidence fixtureOnly does not match suite adapter")
	}
	if evidence.TargetAdapter != "" && evidence.TargetAdapter != suite.Target.Adapter.Kind {
		return nil, errors.New("signed evidence targetAdapter does not match suite adapter")
	}
	eligibility := "application"
	if evidence.AppEvidenceEligible == nil && evidence.FixtureOnly == nil {
		eligibility = "legacy-non-production-non-evidence"
	}
	var evidenceFinishedAt time.Time
	if evidence.FinishedAt != "" {
		parsed, err := time.Parse(time.RFC3339, evidence.FinishedAt)
		if err != nil {
			return nil, fmt.Errorf("signed evidence finishedAt: %w", err)
		}
		evidenceFinishedAt = parsed.UTC()
	}
	contentDigest, err := suiteContentDigest(admitted.Evidence.Files)
	if err != nil {
		return nil, err
	}
	return &SuiteRelease{
		ID:       "vsr-" + strings.TrimPrefix(admitted.Descriptor.Digest, "sha256:")[:16],
		SourceID: admitted.Source.ID, SuiteDigest: admitted.Descriptor.Digest,
		SourceFingerprint: admitted.SourceFingerprint, ContentDigest: contentDigest,
		Suite: suite, WorkflowTemplate: workflow, TrustTier: admitted.Source.TrustTier,
		Unsigned: admitted.Evidence.Unsigned, EvidenceDigest: admitted.Evidence.TestEvidenceDigest,
		EvidenceFinishedAt: evidenceFinishedAt,
		Eligibility:        eligibility, LegacyException: legacyAllowed, AdmittedAt: now.UTC(),
	}, nil
}

func validateSuiteAdapter(suite *Suite) error {
	a := &suite.Target.Adapter
	if a.Kind != "helm" && a.Kind != "manifests" {
		return errors.New("suite target.adapter.kind must be helm or manifests")
	}
	if a.Path != "" && !safeSuitePath(a.Path) || a.ArtifactPath != "" && !safeSuitePath(a.ArtifactPath) {
		return errors.New("suite adapter paths must be confined relative paths")
	}
	if a.FixtureOnly {
		if a.Kind != "manifests" || suite.Target.Component != "" || a.Path == "" || a.ArtifactPath != "" {
			return errors.New("fixtureOnly suites must use a manifests fixture without an application component")
		}
		if len(suite.ExecutableProfiles) != 1 || suite.ExecutableProfiles[0] != ProfileCI {
			return errors.New("fixtureOnly suites require executableProfiles: [ci]")
		}
		return nil
	}
	if suite.Target.Component == "" {
		return errors.New("artifact-bound suite target.component is required")
	}
	if a.Kind == "manifests" && a.ArtifactPath == "" {
		return errors.New("artifact-bound manifests suites require adapter.artifactPath")
	}
	if a.Kind == "helm" && (a.Path != "" || a.ArtifactPath != "") {
		return errors.New("helm suites do not accept manifests adapter paths")
	}
	return nil
}

func safeSuitePath(value string) bool {
	return value != "" && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}

func decodeSingleYAML(raw []byte, out any, knownFields bool) error {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(knownFields)
	if err := decoder.Decode(out); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return err
		}
		return errors.New("multiple YAML documents are forbidden")
	}
	return nil
}

func suiteContentDigest(files map[string][]byte) (string, error) {
	if len(files) == 0 {
		return "", errors.New("signed suite contains no files")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if !safeSuitePath(name) {
			return "", fmt.Errorf("unsafe signed suite file path %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(strconv.Itoa(len(name))))
		h.Write([]byte{':'})
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write(files[name])
		h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ValidateWorkflowTemplate rejects executable content outside platform policy.
func ValidateWorkflowTemplate(raw []byte, suite *Suite, grant *SuiteGrant) error {
	if suite == nil {
		return errors.New("suite is required")
	}
	var document map[string]any
	if err := decodeSingleYAML(raw, &document, false); err != nil {
		return fmt.Errorf("decode WorkflowTemplate: %w", err)
	}
	if document["apiVersion"] != "argoproj.io/v1alpha1" || document["kind"] != "WorkflowTemplate" {
		return errors.New("signed artifact must contain exactly one argoproj.io/v1alpha1 WorkflowTemplate")
	}
	metadata, _ := document["metadata"].(map[string]any)
	if metadata == nil || metadata["name"] == "" || metadata["namespace"] != nil {
		return errors.New("WorkflowTemplate metadata requires a name and forbids a suite-selected namespace")
	}
	spec, _ := document["spec"].(map[string]any)
	if spec == nil || spec["entrypoint"] != suite.Entrypoint {
		return errors.New("WorkflowTemplate spec.entrypoint does not match suite entrypoint")
	}
	if grant != nil && grant.SideEffect != SideEffectReadOnly && spec["onExit"] == nil {
		return errors.New("synthetic or mutating suites require an onExit cleanup handler")
	}
	if err := inspectWorkflowValue(document, ""); err != nil {
		return err
	}
	templates, _ := spec["templates"].([]any)
	if len(templates) == 0 {
		return errors.New("WorkflowTemplate contains no templates")
	}
	for _, item := range templates {
		template, _ := item.(map[string]any)
		if template == nil {
			return errors.New("invalid WorkflowTemplate entry")
		}
		if _, found := template["resource"]; found {
			return errors.New("resource templates and suite-created RBAC are forbidden in real-environment verification")
		}
		if _, found := template["suspend"]; found {
			return errors.New("suspend templates are forbidden")
		}
		if httpTemplate, found := template["http"].(map[string]any); found && (grant == nil || grant.SideEffect == SideEffectReadOnly) {
			method, _ := httpTemplate["method"].(string)
			if method == "" {
				method = "GET"
			}
			if method != "GET" && method != "HEAD" {
				return errors.New("readOnly suites permit only GET or HEAD http templates")
			}
		}
	}
	return nil
}

func inspectWorkflowValue(value any, key string) error {
	switch typed := value.(type) {
	case map[string]any:
		for k, child := range typed {
			switch k {
			case "workflowTemplateRef", "clusterWorkflowTemplateRef", "templateRef":
				return fmt.Errorf("%s references are forbidden; all executable content must be signed", k)
			case "serviceAccountName":
				return errors.New("serviceAccountName overrides are forbidden; the environment grant binds the ServiceAccount")
			case "podSpecPatch", "synchronization":
				return fmt.Errorf("%s overrides are reserved for the platform renderer", k)
			case "hostPath":
				return errors.New("hostPath volumes are forbidden")
			case "hostNetwork", "hostPID", "hostIPC", "hostPort":
				return fmt.Errorf("%s is forbidden", k)
			case "automountServiceAccountToken", "nodeName", "nodeSelector":
				return fmt.Errorf("%s is reserved for the platform renderer", k)
			case "secretKeyRef", "secretRef", "secretName", "configMapRef", "configMapKeyRef", "configMap":
				return fmt.Errorf("%s is forbidden without a platform-approved reference", k)
			case "runAsNonRoot", "readOnlyRootFilesystem":
				if allowed, ok := child.(bool); !ok || !allowed {
					return fmt.Errorf("%s must be true when specified by a suite", k)
				}
			case "add":
				if key == "capabilities" {
					values, ok := child.([]any)
					if !ok || len(values) != 0 {
						return errors.New("capabilities.add is forbidden")
					}
				}
			case "privileged", "allowPrivilegeEscalation":
				if allowed, _ := child.(bool); allowed {
					return fmt.Errorf("%s=true is forbidden", k)
				}
			case "image":
				image, _ := child.(string)
				if !digestPinnedImage(image) {
					return fmt.Errorf("image %q must be digest-pinned", image)
				}
			case "parallelism":
				if numericWorkflowField(child) > 20 {
					return errors.New("parallelism exceeds the platform limit")
				}
			case "limit":
				if key == "retryStrategy" && numericWorkflowField(child) > 3 {
					return errors.New("retryStrategy.limit exceeds the platform limit")
				}
			}
			if err := inspectWorkflowValue(child, k); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := inspectWorkflowValue(child, key); err != nil {
				return err
			}
		}
	}
	return nil
}

func numericWorkflowField(value any) int64 {
	switch typed := value.(type) {
	case int:
		return int64(typed)
	case int64:
		return typed
	case float64:
		return int64(typed)
	case string:
		parsed, _ := strconv.ParseInt(typed, 10, 64)
		return parsed
	default:
		return 0
	}
}

func digestPinnedImage(image string) bool {
	at := strings.LastIndex(image, "@sha256:")
	if at <= 0 || len(image) != at+72 {
		return false
	}
	for _, r := range image[at+8:] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
