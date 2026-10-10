package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const awsPlan = "../../testdata/plans/aws.json"

func runCLI(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out, errb bytes.Buffer
	err := run(args, &out, &errb)
	return out.String() + errb.String(), err
}

func TestTextDefault(t *testing.T) {
	out, err := runCLI(t, "--config", "", awsPlan)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "6 critical, 2 high, 1 medium") {
		t.Fatalf("got %q", out[:60])
	}
}

func TestGateExitCodes(t *testing.T) {
	cfg := "../../examples/tfplan-triage.yml"
	if _, err := runCLI(t, "--config", cfg, awsPlan); !errors.Is(err, errGate) {
		t.Fatalf("want gate failure, got %v", err)
	}
	if _, err := runCLI(t, "--config", cfg, "--labels", "approved-destroy, approved-security", awsPlan); err != nil {
		t.Fatalf("labels should approve: %v", err)
	}
	if _, err := runCLI(t, "--config", cfg, "--fail-on", "none", awsPlan); err != nil {
		t.Fatalf("--fail-on none overrides config: %v", err)
	}
	if _, err := runCLI(t, "--fail-on", "medium", "../../testdata/plans/local.json"); !errors.Is(err, errGate) {
		t.Fatalf("drift is medium: %v", err)
	}
}

func TestOutputs(t *testing.T) {
	dir := t.TempDir()
	md, js := filepath.Join(dir, "r.md"), filepath.Join(dir, "r.json")
	if _, err := runCLI(t, "--format", "markdown", "--output", md, "--json-output", js, "--title", "prod",
		"--tf-dir", "../../testdata/src/aws/head", awsPlan); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(md)
	if err != nil || !strings.HasPrefix(string(b), "<!-- tfplan-triage:prod -->") {
		t.Fatalf("markdown: %v %q", err, b)
	}
	if !strings.Contains(string(b), "is not set in the source") {
		t.Fatal("--tf-dir should feed prevent_destroy into findings")
	}
	var rep struct {
		Result struct {
			Findings []map[string]any `json:"findings"`
		} `json:"result"`
		Gate struct {
			Blocked bool `json:"blocked"`
		} `json:"gate"`
	}
	b, _ = os.ReadFile(js)
	if err := json.Unmarshal(b, &rep); err != nil || len(rep.Result.Findings) != 10 || rep.Gate.Blocked {
		t.Fatalf("json: %v %d", err, len(rep.Result.Findings))
	}
}

func TestStdin(t *testing.T) {
	f, err := os.Open(awsPlan)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	old := os.Stdin
	os.Stdin = f
	defer func() { os.Stdin = old }()
	out, err := runCLI(t, "--format", "json", "-")
	if err != nil || !strings.Contains(out, `"destroy-stateful"`) {
		t.Fatalf("%v %q", err, out)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no args":        {},
		"two plans":      {awsPlan, awsPlan},
		"bad format":     {"--format", "xml", awsPlan},
		"bad fail-on":    {"--fail-on", "severe", awsPlan},
		"missing plan":   {"nope.json"},
		"missing config": {"--config", "nope.yml", awsPlan},
		"bad tf-dir":     {"--tf-dir", t.TempDir(), awsPlan},
		"not a plan":     {"../../examples/tfplan-triage.yml"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := runCLI(t, args...)
			if err == nil || errors.Is(err, errGate) {
				t.Fatalf("want usage error, got %v", err)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	out, err := runCLI(t, "--version")
	if err != nil || strings.TrimSpace(out) != "dev" {
		t.Fatal(out, err)
	}
}
