package planlimits

// LimitExceededError is the transport-safe, machine-readable plan denial. It
// implements huma.StatusError without coupling the generic package to Huma.
type LimitExceededError struct {
	Type         string `json:"type,omitempty"`
	Title        string `json:"title,omitempty"`
	Status       int    `json:"status"`
	Detail       string `json:"detail"`
	Code         string `json:"code"`
	LimitKind    string `json:"limitKind"`
	Limit        string `json:"limit"`
	CurrentUsage *int64 `json:"currentUsage,omitempty"`
	MaxAllowed   *int64 `json:"maxAllowed,omitempty"`
	Requested    *int64 `json:"requested,omitempty"`
	UpgradeURL   string `json:"upgradeUrl,omitempty"`
}

func (e *LimitExceededError) Error() string  { return e.Detail }
func (e *LimitExceededError) GetStatus() int { return e.Status }

// LimitsUnavailableError indicates that enforcement could not resolve limits.
// The cause remains available for logs/errors.Is but is not exposed in JSON.
type LimitsUnavailableError struct {
	Status int    `json:"status"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Code   string `json:"code"`
	cause  error
}

func (e *LimitsUnavailableError) Error() string  { return e.Detail }
func (e *LimitsUnavailableError) GetStatus() int { return e.Status }
func (e *LimitsUnavailableError) Unwrap() error  { return e.cause }
