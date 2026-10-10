package triage

import "sort"

// Approval lets a PR label approve findings that would otherwise fail the
// check, for example `approved-destroy` for destroy-stateful findings.
type Approval struct {
	Label string   `yaml:"label" json:"label"`
	Rules []string `yaml:"rules" json:"rules,omitempty"`
	// MinSeverity limits the approval to findings at or above a level;
	// empty means any level.
	MinSeverity string `yaml:"min_severity" json:"min_severity,omitempty"`
}

// Gate is the outcome of applying fail-on and approvals to a result.
type Gate struct {
	FailOn   string   `json:"fail_on"`
	Labels   []string `json:"labels"`
	Blocked  bool     `json:"blocked"`
	Blocking int      `json:"blocking"`
	Approved int      `json:"approved"`
	// MissingLabels lists labels that would unblock the check.
	MissingLabels []string `json:"missing_labels,omitempty"`
}

func (ap Approval) covers(f Finding) bool {
	if ap.MinSeverity != "" {
		min, err := ParseSeverity(ap.MinSeverity)
		if err != nil || f.Severity < min {
			return false
		}
	}
	if len(ap.Rules) == 0 {
		return true
	}
	for _, r := range ap.Rules {
		if r == f.Rule {
			return true
		}
	}
	return false
}

// ApplyGate marks findings at or above failOn as blocking unless a
// configured approval covers them and its label is on the PR. It mutates
// res.Findings and returns the summary.
func ApplyGate(res *Result, failOn Severity, failOnName string, approvals []Approval, labels []string) Gate {
	have := map[string]bool{}
	for _, l := range labels {
		have[l] = true
	}
	g := Gate{FailOn: failOnName, Labels: append([]string{}, labels...)}
	missing := map[string]bool{}
	for i := range res.Findings {
		f := &res.Findings[i]
		f.Blocking, f.NeedsLabel, f.ApprovedBy = false, "", ""
		if f.Severity < failOn {
			continue
		}
		var candidate string
		for _, ap := range approvals {
			if !ap.covers(*f) {
				continue
			}
			if have[ap.Label] {
				f.ApprovedBy = ap.Label
				break
			}
			if candidate == "" {
				candidate = ap.Label
			}
		}
		if f.ApprovedBy != "" {
			g.Approved++
			continue
		}
		f.Blocking = true
		f.NeedsLabel = candidate
		g.Blocking++
		if candidate != "" {
			missing[candidate] = true
		}
	}
	g.Blocked = g.Blocking > 0
	for l := range missing {
		g.MissingLabels = append(g.MissingLabels, l)
	}
	sort.Strings(g.MissingLabels)
	return g
}
