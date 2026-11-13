package resourcetargets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"sync"
)

type ProviderDescriptor struct {
	Capability      string          `json:"capability"`
	ResourceKinds   []string        `json:"resourceKinds"`
	Actions         []Action        `json:"actions"`
	ConfigSchema    json.RawMessage `json:"configSchema"`
	SelectionSchema json.RawMessage `json:"selectionSchema"`
	UISchema        json.RawMessage `json:"uiSchema"`
	SupportsDefault bool            `json:"supportsDefault"`
}

// Provider is deliberately a pure projection-based contract: no HTTP client,
// secret loader, or cluster connection is available to implementations.
type Provider interface {
	Describe() ProviderDescriptor
	NormalizeConfig(raw json.RawMessage) (json.RawMessage, error)
	ValidateRegistration(snapshot ResourceSnapshot, config json.RawMessage) error
	Resolve(target *Target, snapshot ResourceSnapshot) (Binding, Readiness, error)
	ValidateSelection(target *Target, selection json.RawMessage) (json.RawMessage, ApprovalPolicy, error)
}

type Registry struct {
	mu        sync.RWMutex
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) (*Registry, error) {
	r := &Registry{providers: map[string]Provider{}}
	for _, p := range providers {
		if err := r.Register(p); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func DefaultRegistry() *Registry {
	r, err := NewRegistry(deploymentClusterProvider{}, grafanaProvider{})
	if err != nil {
		panic(err)
	}
	return r
}

func (r *Registry) Register(p Provider) error {
	if p == nil {
		return fmt.Errorf("resourcetargets: nil provider")
	}
	d := p.Describe()
	if d.Capability == "" || len(d.ResourceKinds) == 0 || len(d.Actions) == 0 {
		return fmt.Errorf("resourcetargets: incomplete provider descriptor")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[d.Capability]; exists {
		return fmt.Errorf("resourcetargets: provider %q already registered", d.Capability)
	}
	r.providers[d.Capability] = p
	return nil
}

func (r *Registry) Provider(capability string) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[capability]
	return p, ok
}

func (r *Registry) Descriptors() []ProviderDescriptor {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderDescriptor, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p.Describe())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Capability < out[j].Capability })
	return out
}

func decodeStrict(raw json.RawMessage, out any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%w: request must contain one JSON object", ErrInvalidInput)
	}
	return nil
}

func emptyObject(raw json.RawMessage) bool {
	var obj map[string]json.RawMessage
	if err := decodeStrict(raw, &obj); err != nil {
		return false
	}
	return len(obj) == 0
}
