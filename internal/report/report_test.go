package report

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gratycodes/tfplan-triage/internal/config"
	"github.com/gratycodes/tfplan-triage/internal/plan"
	"github.com/gratycodes/tfplan-triage/internal/source"
	"github.com/gratycodes/tfplan-triage/internal/triage"
)

var update = flag.Bool("update", false, "rewrite golden files")

type goldenCase struct {
	name   string
	plan   string
	tfDir  string
	labels []string
	gated  bool
	title  string
}

var cases = []goldenCase{
	{name: "aws", plan: "aws", tfDir: "aws/head"},
	{name: "aws-gated", plan: "aws", gated: true, labels: []string{"approved-destroy"}},
	{name: "aws-approved", plan: "aws", gated: true, labels: []string{"approved-destroy", "approved-security"}, title: "prod"},
	{name: "gcp", plan: "gcp", tfDir: "gcp/head"},
	{name: "azure", plan: "azure", tfDir: "azure/head"},
	{name: "local", plan: "local", tfDir: "local/head"},
}

func build(t *testing.T, c goldenCase) Report {
	t.Helper()
	p, err := plan.Load("../../testdata/plans/" + c.plan + ".json")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	if c.gated {
		cfg, err = config.Load("../../examples/tfplan-triage.yml", true)
		if err != nil {
			t.Fatal(err)
		}
	}
	opts := cfg.Options()
	if c.tfDir != "" {
		pd, err := source.PreventDestroy("../../testdata/src/" + c.tfDir)
		if err != nil {
			t.Fatal(err)
		}
		opts.PreventDestroy = pd
	}
	res := triage.Analyze(p, opts)
	name := cfg.FailOn
	if name == "" {
		name = "none"
	}
	sev, err := triage.ParseSeverity(name)
	if err != nil {
		t.Fatal(err)
	}
	g := triage.ApplyGate(res, sev, name, cfg.Approvals, c.labels)
	return Report{Title: c.title, Result: res, Gate: &g}
}

func golden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/report -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s differs; run go test ./internal/report -update and review the diff\n--- got ---\n%s", path, got)
	}
}

func TestGolden(t *testing.T) {
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := build(t, c)
			for ext, render := range map[string]func(*bytes.Buffer, Report) error{
				"md":   func(b *bytes.Buffer, r Report) error { return Markdown(b, r) },
				"txt":  func(b *bytes.Buffer, r Report) error { return Text(b, r) },
				"json": func(b *bytes.Buffer, r Report) error { return JSON(b, r) },
			} {
				var b bytes.Buffer
				if err := render(&b, r); err != nil {
					t.Fatal(err)
				}
				golden(t, filepath.Join("testdata", c.name+"."+ext), b.Bytes())
			}
		})
	}
}

func TestMarkdownStartsWithMarker(t *testing.T) {
	for _, c := range cases {
		var b bytes.Buffer
		r := build(t, c)
		if err := Markdown(&b, r); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(b.String(), Marker(c.title)+"\n") {
			t.Errorf("%s: comment must start with its marker", c.name)
		}
		if b.Len() > 65536 {
			t.Errorf("%s: comment exceeds GitHub's 65536 character limit", c.name)
		}
	}
	if Marker("") == Marker("prod") {
		t.Error("titles must get distinct markers")
	}
}

func TestMarkdownCapsLargePlans(t *testing.T) {
	res := &triage.Result{}
	for i := 0; i < 500; i++ {
		res.Findings = append(res.Findings, triage.Finding{
			Rule: triage.RuleDestroyStateful, Severity: triage.Critical,
			Address: "aws_s3_bucket.b[" + strings.Repeat("x", 40) + "]", Title: "Deletes bucket: all objects",
			Details: []string{strings.Repeat("detail ", 20)},
		})
	}
	var b bytes.Buffer
	if err := Markdown(&b, Report{Result: res}); err != nil {
		t.Fatal(err)
	}
	if b.Len() > 65536 {
		t.Fatalf("comment is %d bytes", b.Len())
	}
	if !strings.Contains(b.String(), "…and 475 more") {
		t.Fatal("table should be capped")
	}
}

func TestCell(t *testing.T) {
	if got := cell("a|b\nc"); got != `a\|b c` {
		t.Fatal(got)
	}
}
