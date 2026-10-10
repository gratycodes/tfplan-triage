// Command tfplan-triage reads `terraform show -json` plan output and
// reports the changes a reviewer needs to know about, ranked by blast
// radius: destroyed data stores, widened IAM, new internet exposure,
// removed deletion protection and drift.
//
// Exit codes: 0 ok, 1 usage or input error, 2 the gate failed.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/config"
	"github.com/gratycodes/tfplan-triage/internal/plan"
	"github.com/gratycodes/tfplan-triage/internal/report"
	"github.com/gratycodes/tfplan-triage/internal/source"
	"github.com/gratycodes/tfplan-triage/internal/triage"
)

var version = "dev"

const usage = `usage: tfplan-triage [flags] PLAN_JSON

PLAN_JSON is the output of: terraform show -json plan.out > plan.json
(OpenTofu works the same). Use "-" to read stdin.

Flags:
`

// errGate signals a failed gate (exit 2) after reports are written.
var errGate = errors.New("gate failed")

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr)
	switch {
	case err == nil:
	case errors.Is(err, errGate):
		os.Exit(2)
	case errors.Is(err, flag.ErrHelp):
		os.Exit(0)
	default:
		fmt.Fprintln(os.Stderr, "tfplan-triage:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("tfplan-triage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, usage)
		fs.PrintDefaults()
	}
	var (
		format     = fs.String("format", "text", "output format: text, markdown or json")
		output     = fs.String("output", "", "write the report here instead of stdout")
		jsonOutput = fs.String("json-output", "", "also write the JSON report to this file")
		cfgPath    = fs.String("config", "", "policy file (default "+config.DefaultPath+" if present)")
		tfDir      = fs.String("tf-dir", "", "root module directory, to read lifecycle.prevent_destroy (not in plan JSON)")
		failOn     = fs.String("fail-on", "", "fail (exit 2) on unapproved findings at this severity or above: info, low, medium, high, critical, none (overrides config; default none)")
		labels     = fs.String("labels", "", "comma-separated PR labels, used to match approvals")
		title      = fs.String("title", "", "name for this plan in the comment, e.g. prod; keeps several plans in one PR apart")
		showVer    = fs.Bool("version", false, "print the version and exit")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *showVer {
		fmt.Fprintln(stdout, version)
		return nil
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return errors.New("expected exactly one PLAN_JSON argument")
	}

	path, explicit := *cfgPath, true
	if path == "" {
		path, explicit = config.DefaultPath, false
	}
	cfg, err := config.Load(path, explicit)
	if err != nil {
		return err
	}

	p, err := plan.Load(fs.Arg(0))
	if err != nil {
		return err
	}
	opts := cfg.Options()
	if *tfDir != "" {
		pd, err := source.PreventDestroy(*tfDir)
		if err != nil {
			return fmt.Errorf("--tf-dir: %w", err)
		}
		opts.PreventDestroy = pd
	}
	res := triage.Analyze(p, opts)

	gateName := cfg.FailOn
	if *failOn != "" {
		gateName = *failOn
	}
	if gateName == "" {
		gateName = "none"
	}
	gateSev, err := triage.ParseSeverity(gateName)
	if err != nil {
		return fmt.Errorf("--fail-on: %w", err)
	}
	gate := triage.ApplyGate(res, gateSev, strings.ToLower(gateName), cfg.Approvals, splitLabels(*labels))
	rep := report.Report{Title: *title, Result: res, Gate: &gate}

	out := stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	switch *format {
	case "text":
		err = report.Text(out, rep)
	case "markdown", "md":
		err = report.Markdown(out, rep)
	case "json":
		err = report.JSON(out, rep)
	default:
		return fmt.Errorf("unknown --format %q", *format)
	}
	if err != nil {
		return err
	}
	if *jsonOutput != "" {
		f, err := os.Create(*jsonOutput)
		if err != nil {
			return err
		}
		if err := report.JSON(f, rep); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if gate.Blocked {
		return errGate
	}
	return nil
}

func splitLabels(s string) []string {
	var out []string
	for _, l := range strings.Split(s, ",") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
