package triage

import (
	"fmt"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// kindSeverity is the severity of destroying a stateful resource of a
// kind. Data stores and keys are critical; the rest hurt but recover.
func kindSeverity(kind string) Severity {
	switch kind {
	case "cache", "queue", "stream", "address", "dns", "registry":
		return High
	}
	return Critical
}

var actionReasons = map[string]string{
	"delete_because_no_resource_config": "The resource block was removed from the configuration.",
	"delete_because_no_module":          "Its module call was removed from the configuration.",
	"delete_because_wrong_repetition":   "The resource switched between count, for_each and a single instance.",
	"delete_because_count_index":        "count no longer includes this index.",
	"delete_because_each_key":           "for_each no longer includes this key.",
	"delete_because_no_move_target":     "A moved block points at a resource that no longer exists.",
	"replace_because_tainted":           "The object is tainted (a previous apply failed part-way).",
	"replace_by_request":                "Replacement was requested with -replace.",
	"replace_by_triggers":               "A replace_triggered_by reference changed.",
}

func guardState(s Stateful, attrs map[string]any) (on, known bool) {
	if s.GuardAttr == "" || attrs == nil {
		return false, false
	}
	v, ok := attrs[s.GuardAttr]
	if !ok || v == nil {
		return false, true
	}
	want := s.GuardOn
	if want == nil {
		want = true
	}
	return fmt.Sprint(v) == fmt.Sprint(want), true
}

func (a *analyzer) lifecycle(rc *plan.ResourceChange) []Finding {
	s, stateful := a.stateful(rc.Type)
	act := rc.Action()
	before, after := rc.BeforeMap(), rc.AfterMap()
	guardBefore, _ := guardState(s, before)
	guardAfter, _ := guardState(s, after)

	switch act {
	case plan.Delete, plan.Replace:
		if !stateful {
			return []Finding{a.plainDestroy(rc)}
		}
		var title string
		if act == plan.Delete {
			title = fmt.Sprintf("Deletes %s: %s", s.Kind, s.Loss)
		} else {
			title = fmt.Sprintf("Replaces %s: %s", s.Kind, s.Loss)
			if paths := rc.ReplacePaths(); len(paths) > 0 {
				title = fmt.Sprintf("Replaces %s (forced by %s): %s", s.Kind, codeList(paths), s.Loss)
			}
		}
		var d []string
		if act == plan.Replace {
			d = append(d, a.replaceDetails(rc)...)
			if rc.CreateBeforeDestroy() {
				d = append(d, "create_before_destroy is set: the new object is created first, but it starts empty.")
			} else {
				d = append(d, "The old object is destroyed before the new one exists.")
			}
		}
		if r, ok := actionReasons[rc.ActionReason]; ok {
			d = append(d, r)
		}
		for _, amp := range s.Amplifiers {
			if on, _ := plan.Bool(before, amp); on {
				d = append(d, fmt.Sprintf("`%s = true`: the provider deletes the contents too, without asking.", amp))
			}
		}
		switch {
		case s.GuardAttr != "" && guardBefore && !guardAfter && act == plan.Replace:
			d = append(d, fmt.Sprintf("`%s` is on in the current state. This change also turns it off, but the delete uses the current setting, so expect this apply to fail at the delete step; the next apply after it would go through.", s.GuardAttr))
		case s.GuardAttr != "" && guardBefore:
			d = append(d, fmt.Sprintf("`%s` is on in the current state, so the delete should fail at apply time until protection is turned off in an earlier apply.", s.GuardAttr))
		case s.GuardAttr != "":
			d = append(d, fmt.Sprintf("`%s` is off, so the provider will not stop it.", s.GuardAttr))
		}
		if pd, known := a.preventDestroy(rc.Address); known && !pd {
			d = append(d, "`lifecycle { prevent_destroy = true }` is not set in the source.")
		}
		return []Finding{newFinding(rc, RuleDestroyStateful, kindSeverity(s.Kind), title, d...)}

	case plan.Update:
		var out []Finding
		if stateful && s.GuardAttr != "" && guardBefore && !guardAfter {
			out = append(out, newFinding(rc, RuleProtectionRemoved, High,
				fmt.Sprintf("Turns off `%s` on a %s", s.GuardAttr, s.Kind),
				"A later change or `terraform destroy` can now delete it without a separate step."))
		}
		if stateful && !a.noiseOnly(rc) {
			if f, ok := a.unguarded(rc, s, guardAfter); ok {
				out = append(out, f)
			}
		}
		return out

	case plan.Create:
		if stateful {
			if f, ok := a.unguarded(rc, s, guardAfter); ok {
				return []Finding{f}
			}
		}
	}
	return nil
}

func (a *analyzer) plainDestroy(rc *plan.ResourceChange) Finding {
	if rc.Action() == plan.Delete {
		f := newFinding(rc, RuleDestroy, Low, "Deletes "+rc.Type)
		if r, ok := actionReasons[rc.ActionReason]; ok {
			f.Details = append(f.Details, r)
		}
		return f
	}
	title := "Replaces " + rc.Type
	if paths := rc.ReplacePaths(); len(paths) > 0 {
		title += " (forced by " + codeList(paths) + ")"
	}
	f := newFinding(rc, RuleReplace, Low, title, a.replaceDetails(rc)...)
	if r, ok := actionReasons[rc.ActionReason]; ok {
		f.Details = append(f.Details, r)
	}
	return f
}

// replaceDetails shows before -> after for scalar top-level attributes that
// force replacement, never for sensitive ones.
func (a *analyzer) replaceDetails(rc *plan.ResourceChange) []string {
	var d []string
	before, after := rc.BeforeMap(), rc.AfterMap()
	for _, p := range rc.ReplacePaths() {
		top := strings.SplitN(p, ".", 2)[0]
		if top != p {
			continue
		}
		if rc.Sensitive(top) {
			d = append(d, fmt.Sprintf("`%s` changes (sensitive value hidden).", top))
			continue
		}
		bv, av := scalar(before[top]), scalar(after[top])
		if rc.AfterUnknown(top) {
			av = "(known after apply)"
		}
		if bv != "" && av != "" {
			d = append(d, fmt.Sprintf("`%s`: %s → %s", top, bv, av))
		}
	}
	return d
}

func (a *analyzer) unguarded(rc *plan.ResourceChange, s Stateful, guardAfter bool) (Finding, bool) {
	if guardAfter || kindSeverity(s.Kind) < Critical {
		return Finding{}, false
	}
	pd, pdKnown := a.preventDestroy(rc.Address)
	if pd {
		return Finding{}, false
	}
	var fix []string
	if s.GuardAttr != "" {
		want := "true"
		if s.GuardOn != nil {
			want = fmt.Sprintf("%q", s.GuardOn)
		}
		fix = append(fix, fmt.Sprintf("`%s = %s`", s.GuardAttr, want))
	}
	fix = append(fix, "`lifecycle { prevent_destroy = true }`")
	title := fmt.Sprintf("No deletion protection on %s", s.Kind)
	d := []string{"Consider " + strings.Join(fix, " or ") + "."}
	switch {
	case a.opts.PreventDestroy == nil:
		d = append(d, "prevent_destroy was not checked (it is not in plan JSON; pass --tf-dir to read it from the source).")
	case !pdKnown:
		d = append(d, "prevent_destroy could not be read (remote module or a non-literal value).")
	}
	return newFinding(rc, RuleUnguardedStateful, Low, title, d...), true
}

func scalar(v any) string {
	switch x := v.(type) {
	case nil:
		return "null"
	case string:
		return fmt.Sprintf("%q", x)
	case bool:
		return fmt.Sprint(x)
	case fmt.Stringer:
		return x.String()
	}
	return ""
}

func codeList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = "`" + s + "`"
	}
	return strings.Join(q, ", ")
}
