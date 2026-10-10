// Package triage turns a Terraform/OpenTofu plan into ranked findings: the
// handful of changes a reviewer must look at, separated from the noise.
package triage

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// Severity orders findings. The zero value is Info.
type Severity int

// Severities from least to most urgent.
const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// ParseSeverity accepts the lower-case names plus "none", which returns
// a level above Critical so nothing reaches it.
func ParseSeverity(s string) (Severity, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "none" || s == "" {
		return Critical + 1, nil
	}
	for i, n := range severityNames {
		if n == s {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high, critical or none)", s)
}

// MarshalJSON writes the severity as its name.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// UnmarshalJSON reads a severity name.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// Rule identifiers. They appear in reports, config files and approvals,
// so treat them as a stable interface.
const (
	RuleDestroyStateful   = "destroy-stateful"
	RuleProtectionRemoved = "protection-removed"
	RuleIAMWidening       = "iam-widening"
	RuleNetworkExposure   = "network-exposure"
	RuleUnguardedStateful = "unguarded-stateful"
	RuleDrift             = "drift"
	RuleDestroy           = "destroy"
	RuleReplace           = "replace"
)

// Finding is one thing a reviewer should know about.
type Finding struct {
	Rule     string      `json:"rule"`
	Severity Severity    `json:"severity"`
	Address  string      `json:"address"`
	Module   string      `json:"module"`
	Type     string      `json:"type"`
	Action   plan.Action `json:"action"`
	Title    string      `json:"title"`
	Details  []string    `json:"details,omitempty"`
	// Blocking is set by the policy gate when this finding fails the check.
	Blocking bool `json:"blocking,omitempty"`
	// NeedsLabel names the PR label that would approve a blocking finding.
	NeedsLabel string `json:"needs_label,omitempty"`
	// ApprovedBy names the label that approved a finding at or above the
	// fail-on level.
	ApprovedBy string `json:"approved_by,omitempty"`
}

func newFinding(rc *plan.ResourceChange, rule string, sev Severity, title string, details ...string) Finding {
	return Finding{
		Rule:     rule,
		Severity: sev,
		Address:  rc.Address,
		Module:   rc.Module(),
		Type:     rc.Type,
		Action:   rc.Action(),
		Title:    title,
		Details:  details,
	}
}
