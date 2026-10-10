package triage

import "testing"

func gateFixture() *Result {
	return &Result{Findings: []Finding{
		{Rule: RuleDestroyStateful, Severity: Critical, Address: "a"},
		{Rule: RuleIAMWidening, Severity: High, Address: "b"},
		{Rule: RuleNetworkExposure, Severity: Medium, Address: "c"},
	}}
}

var approvals = []Approval{
	{Label: "approved-destroy", Rules: []string{RuleDestroyStateful}},
	{Label: "approved-security", Rules: []string{RuleIAMWidening, RuleNetworkExposure}, MinSeverity: "high"},
}

func TestGateBlocksWithoutLabels(t *testing.T) {
	res := gateFixture()
	g := ApplyGate(res, High, "high", approvals, nil)
	if !g.Blocked || g.Blocking != 2 {
		t.Fatalf("%+v", g)
	}
	if got := g.MissingLabels; len(got) != 2 || got[0] != "approved-destroy" || got[1] != "approved-security" {
		t.Fatalf("missing %v", got)
	}
	if res.Findings[0].NeedsLabel != "approved-destroy" || res.Findings[2].Blocking {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestGatePassesWithLabels(t *testing.T) {
	res := gateFixture()
	g := ApplyGate(res, High, "high", approvals, []string{"approved-destroy", "approved-security"})
	if g.Blocked || g.Approved != 2 {
		t.Fatalf("%+v", g)
	}
	if res.Findings[1].ApprovedBy != "approved-security" {
		t.Fatalf("%+v", res.Findings[1])
	}
}

func TestGatePartialApproval(t *testing.T) {
	res := gateFixture()
	g := ApplyGate(res, High, "high", approvals, []string{"approved-destroy"})
	if !g.Blocked || g.Blocking != 1 || g.MissingLabels[0] != "approved-security" {
		t.Fatalf("%+v", g)
	}
}

func TestGateMinSeverityOnApproval(t *testing.T) {
	res := gateFixture()
	// fail on medium: the medium network finding is not covered by the
	// security approval (min high), so no label can approve it.
	g := ApplyGate(res, Medium, "medium", approvals, []string{"approved-destroy", "approved-security"})
	if !g.Blocked || g.Blocking != 1 || len(g.MissingLabels) != 0 || res.Findings[2].NeedsLabel != "" {
		t.Fatalf("%+v %+v", g, res.Findings[2])
	}
}

func TestGateNone(t *testing.T) {
	sev, _ := ParseSeverity("none")
	g := ApplyGate(gateFixture(), sev, "none", approvals, nil)
	if g.Blocked {
		t.Fatal("none never blocks")
	}
}

func TestGateIsIdempotent(t *testing.T) {
	res := gateFixture()
	ApplyGate(res, High, "high", approvals, nil)
	g := ApplyGate(res, High, "high", approvals, []string{"approved-destroy", "approved-security"})
	if g.Blocked || res.Findings[0].Blocking || res.Findings[0].NeedsLabel != "" {
		t.Fatalf("stale gate state: %+v", res.Findings[0])
	}
}
