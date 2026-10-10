package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseExample(t *testing.T) {
	b, err := os.ReadFile("../../examples/tfplan-triage.yml")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if c.FailOn != "high" || len(c.Approvals) != 2 || c.Approvals[0].Label != "approved-destroy" {
		t.Fatalf("%+v", c)
	}
	o := c.Options()
	if o.ExtraStateful["aws_neptune_cluster"].Kind != "database" || o.ExtraSensitivePorts[8443] == "" || len(o.Ignore) != 1 {
		t.Fatalf("%+v", o)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "fail_onn: high",
		"bad severity":     "fail_on: severe",
		"approval label":   "approvals:\n  - rules: [destroy-stateful]",
		"unknown rule":     "approvals:\n  - label: x\n    rules: [destroy-everything]",
		"approval min sev": "approvals:\n  - label: x\n    min_severity: huge",
		"ignore address":   "ignore:\n  - rules: [drift]",
		"ignore rule":      "ignore:\n  - address: a.b\n    rules: [nope]",
		"stateful kind":    "stateful_types:\n  acme_db: {loss: rows}",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(in)); err == nil {
				t.Fatal("want error")
			}
		})
	}
}

func TestParseEmptyAndDefaults(t *testing.T) {
	c, err := Parse(nil)
	if err != nil || c.FailOn != "" {
		t.Fatal(c, err)
	}
	c, err = Parse([]byte("stateful_types:\n  acme_db: {kind: database}\n"))
	if err != nil || c.StatefulTypes["acme_db"].Loss != "its data" {
		t.Fatal(c, err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, DefaultPath), false); err != nil {
		t.Fatal("missing default file is fine:", err)
	}
	if _, err := Load(filepath.Join(dir, "nope.yml"), true); err == nil {
		t.Fatal("missing explicit file must error")
	}
	p := filepath.Join(dir, "c.yml")
	if err := os.WriteFile(p, []byte("fail_on: critical\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p, true)
	if err != nil || !strings.EqualFold(c.FailOn, "critical") {
		t.Fatal(c, err)
	}
}
