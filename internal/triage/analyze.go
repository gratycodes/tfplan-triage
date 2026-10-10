package triage

import (
	"sort"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// Options tune an analysis. The zero value uses the built-in tables.
type Options struct {
	// ExtraStateful adds or overrides entries of StatefulTypes.
	ExtraStateful map[string]Stateful
	// ExtraSensitivePorts adds to SensitivePorts.
	ExtraSensitivePorts map[int]string
	// PreventDestroy maps resource addresses (without instance keys) to
	// their lifecycle.prevent_destroy setting, read from the source.
	// Nil means the source was not read.
	PreventDestroy map[string]bool
	// Ignore drops findings that match.
	Ignore []IgnoreRule
}

// IgnoreRule suppresses findings by address glob and, optionally, rule.
type IgnoreRule struct {
	Address string   `yaml:"address" json:"address"`
	Rules   []string `yaml:"rules" json:"rules,omitempty"`
	Reason  string   `yaml:"reason" json:"reason,omitempty"`
}

// Counts tallies resource changes by action.
type Counts struct {
	Create  int `json:"create"`
	Update  int `json:"update"`
	Replace int `json:"replace"`
	Delete  int `json:"delete"`
}

func (c *Counts) add(a plan.Action) {
	switch a {
	case plan.Create:
		c.Create++
	case plan.Update:
		c.Update++
	case plan.Replace:
		c.Replace++
	case plan.Delete:
		c.Delete++
	}
}

// Total is the number of resources that change.
func (c Counts) Total() int { return c.Create + c.Update + c.Replace + c.Delete }

// ModuleSummary is the per-module roll-up.
type ModuleSummary struct {
	Module   string    `json:"module"`
	Counts   Counts    `json:"counts"`
	Findings int       `json:"findings"`
	Highest  *Severity `json:"highest,omitempty"`
}

// NoiseGroup collects low-signal updates collapsed in reports.
type NoiseGroup struct {
	Reason    string   `json:"reason"`
	Addresses []string `json:"addresses"`
}

// Change is one resource change that produced no finding.
type Change struct {
	Address string      `json:"address"`
	Action  plan.Action `json:"action"`
	Note    string      `json:"note,omitempty"`
}

// Result is the full triage of one plan.
type Result struct {
	TerraformVersion string          `json:"terraform_version"`
	Totals           Counts          `json:"totals"`
	Drifted          int             `json:"drifted"`
	Findings         []Finding       `json:"findings"`
	Modules          []ModuleSummary `json:"modules"`
	Noise            []NoiseGroup    `json:"noise"`
	Unflagged        []Change        `json:"unflagged"`
	Ignored          int             `json:"ignored"`
	Errored          bool            `json:"errored"`
}

// CountAtLeast counts findings at or above a severity.
func (r *Result) CountAtLeast(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity >= s {
			n++
		}
	}
	return n
}

// CountBySeverity returns the number of findings per severity.
func (r *Result) CountBySeverity() map[Severity]int {
	m := map[Severity]int{}
	for _, f := range r.Findings {
		m[f.Severity]++
	}
	return m
}

type analyzer struct {
	opts           Options
	sensitivePorts map[int]string
	ignored        int
}

func (a *analyzer) stateful(t string) (Stateful, bool) {
	if s, ok := a.opts.ExtraStateful[t]; ok {
		return s, true
	}
	s, ok := StatefulTypes[t]
	return s, ok
}

// preventDestroy looks up the source-level lifecycle setting.
func (a *analyzer) preventDestroy(addr string) (value, known bool) {
	if a.opts.PreventDestroy == nil {
		return false, false
	}
	v, ok := a.opts.PreventDestroy[StripInstanceKeys(addr)]
	return v, ok
}

// StripInstanceKeys removes [0] and ["key"] from an address, so that
// module.db["eu"].aws_db_instance.this[0] becomes
// module.db.aws_db_instance.this.
func StripInstanceKeys(addr string) string {
	var b strings.Builder
	depth, inQuote := 0, false
	for i := 0; i < len(addr); i++ {
		c := addr[i]
		switch {
		case inQuote:
			if c == '\\' {
				i++
			} else if c == '"' {
				inQuote = false
			}
		case c == '"' && depth > 0:
			inQuote = true
		case c == '[':
			depth++
		case c == ']':
			depth--
		case depth == 0:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Analyze triages a plan.
func Analyze(p *plan.Plan, opts Options) *Result {
	a := &analyzer{opts: opts, sensitivePorts: map[int]string{}}
	for k, v := range SensitivePorts {
		a.sensitivePorts[k] = v
	}
	for k, v := range opts.ExtraSensitivePorts {
		a.sensitivePorts[k] = v
	}
	res := &Result{TerraformVersion: p.TerraformVersion, Errored: p.Errored}
	mods := map[string]*ModuleSummary{}
	mod := func(name string) *ModuleSummary {
		if mods[name] == nil {
			mods[name] = &ModuleSummary{Module: name}
		}
		return mods[name]
	}
	noise := map[string][]string{}

	var findings []Finding
	for i := range p.ResourceChanges {
		rc := &p.ResourceChanges[i]
		if rc.Mode != "managed" {
			continue
		}
		act := rc.Action()
		if act != plan.NoOp && act != plan.Read && act != plan.Forget {
			res.Totals.add(act)
			mod(rc.Module()).Counts.add(act)
		}
		var fs []Finding
		fs = append(fs, a.lifecycle(rc)...)
		fs = a.filter(fs)
		findings = append(findings, fs...)
		if len(fs) > 0 {
			continue
		}
		switch {
		case act == plan.Update && a.noiseOnly(rc):
			reason := noiseLabel(rc.ChangedAttributes())
			noise[reason] = append(noise[reason], rc.Address)
		case act == plan.Forget:
			res.Unflagged = append(res.Unflagged, Change{rc.Address, act, "removed from state, object kept"})
		case rc.Moved() && act == plan.NoOp:
			res.Unflagged = append(res.Unflagged, Change{rc.Address, "move", "moved from " + rc.PreviousAddress})
		case rc.Imported():
			res.Unflagged = append(res.Unflagged, Change{rc.Address, "import", ""})
		case act == plan.Create || act == plan.Update:
			res.Unflagged = append(res.Unflagged, Change{Address: rc.Address, Action: act})
		}
	}
	for i := range p.ResourceDrift {
		rc := &p.ResourceDrift[i]
		if rc.Mode != "managed" {
			continue
		}
		fs := a.filter(a.drift(rc))
		if len(fs) > 0 {
			res.Drifted++
		}
		findings = append(findings, fs...)
	}
	for _, f := range findings {
		m := mod(f.Module)
		m.Findings++
		if m.Highest == nil || f.Severity > *m.Highest {
			s := f.Severity
			m.Highest = &s
		}
	}
	SortFindings(findings)
	res.Findings = findings
	if res.Findings == nil {
		res.Findings = []Finding{}
	}
	for _, m := range mods {
		res.Modules = append(res.Modules, *m)
	}
	sort.Slice(res.Modules, func(i, j int) bool { return res.Modules[i].Module < res.Modules[j].Module })
	for reason, addrs := range noise {
		sort.Strings(addrs)
		res.Noise = append(res.Noise, NoiseGroup{reason, addrs})
	}
	sort.Slice(res.Noise, func(i, j int) bool { return res.Noise[i].Reason < res.Noise[j].Reason })
	sort.Slice(res.Unflagged, func(i, j int) bool { return res.Unflagged[i].Address < res.Unflagged[j].Address })
	res.Ignored = a.ignored
	return res
}

var rulePriority = map[string]int{
	RuleDestroyStateful:   0,
	RuleIAMWidening:       1,
	RuleNetworkExposure:   2,
	RuleProtectionRemoved: 3,
	RuleDrift:             4,
	RuleUnguardedStateful: 5,
	RuleReplace:           6,
	RuleDestroy:           7,
}

// SortFindings orders by severity, then rule, then address.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if rulePriority[a.Rule] != rulePriority[b.Rule] {
			return rulePriority[a.Rule] < rulePriority[b.Rule]
		}
		return a.Address < b.Address
	})
}
