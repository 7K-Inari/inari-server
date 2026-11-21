package verification

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const GenericOutcomeSchema = "inari.verification.outcome/v1"

// OutcomeCheck is a bounded generic application check result.
type OutcomeCheck struct {
	Name    string `json:"name"`
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// GenericOutcome is the optional typed Workflow output for application runs.
type GenericOutcome struct {
	Schema    string         `json:"schema"`
	Result    string         `json:"result"`
	Checks    []OutcomeCheck `json:"checks,omitempty"`
	ExpiresAt string         `json:"expiresAt"`
}

func ParseGenericOutcome(raw []byte, maxBytes int, now time.Time) (*GenericOutcome, time.Time, error) {
	if maxBytes <= 0 || maxBytes > 1<<20 {
		maxBytes = 65536
	}
	if len(raw) == 0 {
		return nil, time.Time{}, errors.New("outcome_missing: typed verification outcome is required")
	}
	if len(raw) > maxBytes {
		return nil, time.Time{}, errors.New("outcome_invalid: outcome exceeds the grant size limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var outcome GenericOutcome
	if err := decoder.Decode(&outcome); err != nil {
		return nil, time.Time{}, fmt.Errorf("outcome_invalid: %w", err)
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, time.Time{}, errors.New("outcome_invalid: multiple JSON values")
	}
	if outcome.Schema != GenericOutcomeSchema || (outcome.Result != "passed" && outcome.Result != "failed") {
		return nil, time.Time{}, errors.New("outcome_invalid: unexpected schema or result")
	}
	if len(outcome.Checks) > 100 {
		return nil, time.Time{}, errors.New("outcome_invalid: too many checks")
	}
	seen := map[string]bool{}
	for _, check := range outcome.Checks {
		if strings.TrimSpace(check.Name) == "" || seen[check.Name] {
			return nil, time.Time{}, errors.New("outcome_invalid: check names must be nonempty and unique")
		}
		seen[check.Name] = true
		if check.State != "passed" && check.State != "failed" && check.State != "skipped" {
			return nil, time.Time{}, fmt.Errorf("outcome_invalid: check %q has invalid state", check.Name)
		}
		if len([]rune(check.Message)) > 512 {
			return nil, time.Time{}, errors.New("outcome_invalid: check message is too long")
		}
		if outcome.Result == "passed" && check.State != "passed" {
			return nil, time.Time{}, errors.New("outcome_invalid: passing outcome contains a non-passing check")
		}
	}
	expiresAt, err := time.Parse(time.RFC3339, outcome.ExpiresAt)
	if err != nil {
		return nil, time.Time{}, errors.New("outcome_invalid: expiresAt must be RFC3339")
	}
	expiresAt = expiresAt.UTC()
	if outcome.Result == "passed" && !expiresAt.After(now) {
		return nil, time.Time{}, errors.New("verification_stale: outcome evidence is expired")
	}
	return &outcome, expiresAt, nil
}
