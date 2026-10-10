package triage

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// change builds a plan with one resource change. before/after are JSON
// objects or "null".
func change(t *testing.T, typ string, actions string, before, after string, extra ...string) *plan.Plan {
	t.Helper()
	body := `{"address":"` + typ + `.this","mode":"managed","type":"` + typ + `","name":"this",
		"change":{"actions":` + actions + `,"before":` + before + `,"after":` + after
	for _, e := range extra {
		body += "," + e
	}
	body += `}}`
	return planOf(t, `"resource_changes":[`+body+`]`)
}

func planOf(t *testing.T, inner string) *plan.Plan {
	t.Helper()
	p, err := plan.Decode(strings.NewReader(`{"format_version":"1.2",` + inner + `}`))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func only(t *testing.T, res *Result, rule string) []Finding {
	t.Helper()
	var out []Finding
	for _, f := range res.Findings {
		if f.Rule == rule {
			out = append(out, f)
		}
	}
	return out
}

func one(t *testing.T, res *Result, rule string) Finding {
	t.Helper()
	fs := only(t, res, rule)
	if len(fs) != 1 {
		b, _ := json.MarshalIndent(res.Findings, "", "  ")
		t.Fatalf("want exactly one %s finding, got %d:\n%s", rule, len(fs), b)
	}
	return fs[0]
}

func none(t *testing.T, res *Result, rule string) {
	t.Helper()
	if fs := only(t, res, rule); len(fs) > 0 {
		b, _ := json.MarshalIndent(fs, "", "  ")
		t.Fatalf("want no %s findings, got:\n%s", rule, b)
	}
}

func hasDetail(f Finding, sub string) bool {
	for _, d := range append([]string{f.Title}, f.Details...) {
		if strings.Contains(d, sub) {
			return true
		}
	}
	return false
}

// policy wraps an IAM policy document as a JSON string value.
func policy(doc string) string {
	b, _ := json.Marshal(doc)
	return string(b)
}
