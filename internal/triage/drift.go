package triage

import (
	"fmt"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// drift reports objects that changed outside Terraform (resource_drift).
// These matter because the plan was computed against the drifted state:
// someone's hand-made fix may be about to be reverted, or a resource that
// was deleted by hand is about to be recreated empty.
func (a *analyzer) drift(rc *plan.ResourceChange) []Finding {
	s, stateful := a.stateful(rc.Type)
	switch rc.Action() {
	case plan.Delete:
		if stateful {
			return []Finding{newFinding(rc, RuleDrift, High,
				fmt.Sprintf("Deleted outside Terraform: %s", s.Kind),
				"The object no longer exists. If the configuration still declares it, this plan creates a new, empty one.")}
		}
		return []Finding{newFinding(rc, RuleDrift, Medium, "Deleted outside Terraform",
			"If the configuration still declares it, this plan recreates it.")}
	case plan.Update:
		changed := rc.ChangedAttributes()
		if len(changed) == 0 {
			return nil
		}
		sev := Medium
		if a.noiseOnly(rc) {
			sev = Low
		}
		var d []string
		if stateful && s.GuardAttr != "" {
			before := guardState(s, rc.BeforeMap())
			after := guardState(s, rc.AfterMap())
			if before && !after {
				sev = High
				d = append(d, fmt.Sprintf("`%s` was turned off by hand.", s.GuardAttr))
			}
		}
		d = append(d, "Applying this plan reverts the out-of-band change unless the configuration was updated to match.")
		return []Finding{newFinding(rc, RuleDrift, sev,
			fmt.Sprintf("Changed outside Terraform: %s", codeList(limit(changed, 6))), d...)}
	}
	return nil
}

func limit(items []string, n int) []string {
	if len(items) <= n {
		return items
	}
	out := append([]string{}, items[:n]...)
	return append(out, fmt.Sprintf("+%d more", len(items)-n))
}

// noiseOnly reports whether every changed attribute is in noiseAttrs.
func (a *analyzer) noiseOnly(rc *plan.ResourceChange) bool {
	changed := rc.ChangedAttributes()
	if len(changed) == 0 {
		return false
	}
	for _, c := range changed {
		if !noiseAttrs[c] {
			return false
		}
	}
	return true
}

// noiseLabel names the kind of noise, e.g. "tags only".
func noiseLabel(changed []string) string {
	kinds := map[string]bool{}
	for _, c := range changed {
		switch {
		case strings.Contains(c, "tags"):
			kinds["tags"] = true
		case strings.Contains(c, "labels"):
			kinds["labels"] = true
		default:
			kinds[c] = true
		}
	}
	var parts []string
	for _, k := range []string{"tags", "labels", "description"} {
		if kinds[k] {
			parts = append(parts, k)
		}
	}
	return strings.Join(parts, " and ") + " only"
}
