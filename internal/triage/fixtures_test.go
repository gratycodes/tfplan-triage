package triage

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// These plans were produced by real terraform/tofu runs (testdata/src).
// The expectations pin what a reviewer should see for each scenario.
func TestFixtures(t *testing.T) {
	want := map[string][]string{
		"aws": {
			"critical destroy-stateful aws_s3_bucket.scratch",
			"critical destroy-stateful aws_s3_bucket.statements",
			"critical destroy-stateful module.ledger_db.aws_db_instance.this",
			"critical destroy-stateful module.ledger_db.aws_kms_key.legacy",
			"critical iam-widening aws_iam_role_policy_attachment.ci_admin",
			"critical network-exposure aws_vpc_security_group_ingress_rule.ssh_debug",
			"high iam-widening aws_iam_role_policy.ci_deployer",
			"high network-exposure aws_s3_bucket_public_access_block.statements",
			"medium network-exposure aws_vpc_security_group_ingress_rule.https_public",
			"low replace aws_s3_bucket_public_access_block.statements",
		},
		"gcp": {
			"critical destroy-stateful google_compute_disk.cache",
			"critical destroy-stateful google_kms_crypto_key.card_vault",
			"critical destroy-stateful google_sql_database_instance.ledger",
			"critical destroy-stateful google_storage_bucket.exports",
			"critical iam-widening google_storage_bucket_iam_member.reports_partner",
			"critical network-exposure google_compute_firewall.ssh_iap_debug",
			"high iam-widening google_project_iam_member.ci_owner",
			"medium network-exposure google_compute_address.partner_sftp",
		},
		"azure": {
			"critical destroy-stateful azurerm_key_vault.app",
			"critical destroy-stateful azurerm_storage_account.ledger",
			"critical iam-widening azurerm_role_assignment.ci_uaa",
			"critical network-exposure azurerm_network_security_rule.rdp",
			"medium network-exposure azurerm_public_ip.jump",
		},
		"local": {
			"medium drift local_file.feature_flags",
			"low replace local_file.routing",
			"low replace random_password.webhook_secret",
		},
	}
	for name, exp := range want {
		t.Run(name, func(t *testing.T) {
			p, err := plan.Load("../../testdata/plans/" + name + ".json")
			if err != nil {
				t.Fatal(err)
			}
			res := Analyze(p, Options{})
			var got []string
			for _, f := range res.Findings {
				got = append(got, fmt.Sprintf("%s %s %s", f.Severity, f.Rule, f.Address))
			}
			if strings.Join(got, "\n") != strings.Join(exp, "\n") {
				t.Fatalf("got:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(exp, "\n"))
			}
		})
	}
}

// The local plan contains a random_password; its value must never appear
// in a finding.
func TestFixtureSecretsNeverLeak(t *testing.T) {
	p, err := plan.Load("../../testdata/plans/local.json")
	if err != nil {
		t.Fatal(err)
	}
	var secret string
	for _, rc := range p.ResourceChanges {
		if rc.Type == "random_password" {
			secret = plan.Str(rc.BeforeMap(), "result")
		}
	}
	if len(secret) < 16 {
		t.Fatalf("fixture should carry the old password in state, got %q", secret)
	}
	for _, f := range Analyze(p, Options{}).Findings {
		for _, s := range append([]string{f.Title}, f.Details...) {
			if strings.Contains(s, secret) {
				t.Fatalf("secret leaked in %s: %s", f.Address, s)
			}
		}
	}
}
