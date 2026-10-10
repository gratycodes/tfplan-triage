package triage

import "testing"

func TestDeleteStatefulIsCritical(t *testing.T) {
	p := change(t, "aws_s3_bucket", `["delete"]`, `{"bucket":"b","force_destroy":true}`, `null`,
		`"x":1`)
	p.ResourceChanges[0].ActionReason = "delete_because_no_resource_config"
	f := one(t, Analyze(p, Options{}), RuleDestroyStateful)
	if f.Severity != Critical {
		t.Fatalf("severity %s", f.Severity)
	}
	if !hasDetail(f, "`force_destroy = true`: the provider empties it first, so a non-empty bucket is deleted") || !hasDetail(f, "removed from the configuration") {
		t.Fatalf("details: %v", f.Details)
	}
}

func TestReplaceStatefulNamesForcingAttribute(t *testing.T) {
	p := change(t, "aws_db_instance", `["delete","create"]`,
		`{"storage_encrypted":false,"deletion_protection":false}`,
		`{"storage_encrypted":true,"deletion_protection":false}`,
		`"replace_paths":[["storage_encrypted"]]`)
	f := one(t, Analyze(p, Options{}), RuleDestroyStateful)
	if f.Title != "Replaces database (forced by `storage_encrypted`): all data and automated backups" {
		t.Fatalf("title %q", f.Title)
	}
	for _, want := range []string{"`storage_encrypted`: false → true", "destroyed before the new one exists", "`deletion_protection` is off"} {
		if !hasDetail(f, want) {
			t.Errorf("missing %q in %v", want, f.Details)
		}
	}
}

func TestReplaceWithProtectionOnWarnsApplyWillFail(t *testing.T) {
	p := change(t, "google_sql_database_instance", `["delete","create"]`,
		`{"region":"europe-west1","deletion_protection":true}`,
		`{"region":"europe-west2","deletion_protection":false}`,
		`"replace_paths":[["region"]]`)
	f := one(t, Analyze(p, Options{}), RuleDestroyStateful)
	if !hasDetail(f, "expect this apply to fail at the delete step") {
		t.Fatalf("details: %v", f.Details)
	}
	// The protection flip is part of the destroy finding, not a second one.
	none(t, Analyze(p, Options{}), RuleProtectionRemoved)
}

func TestDatabaseBackupAmplifiers(t *testing.T) {
	p := change(t, "aws_db_instance", `["delete"]`,
		`{"identifier":"db","skip_final_snapshot":true,"delete_automated_backups":true,"deletion_protection":false}`, `null`)
	f := one(t, Analyze(p, Options{}), RuleDestroyStateful)
	for _, want := range []string{"no final snapshot is taken before the database", "automated backups are deleted with the database"} {
		if !hasDetail(f, want) {
			t.Errorf("missing %q in %v", want, f.Details)
		}
	}
}

func TestCreateBeforeDestroyStillLosesData(t *testing.T) {
	p := change(t, "aws_ebs_volume", `["create","delete"]`, `{"size":10}`, `{"size":10}`,
		`"replace_paths":[["availability_zone"]]`)
	f := one(t, Analyze(p, Options{}), RuleDestroyStateful)
	if !hasDetail(f, "starts empty") {
		t.Fatalf("details: %v", f.Details)
	}
}

func TestLowerSeverityKinds(t *testing.T) {
	p := change(t, "aws_sqs_queue", `["delete"]`, `{"name":"q"}`, `null`)
	if f := one(t, Analyze(p, Options{}), RuleDestroyStateful); f.Severity != High {
		t.Fatalf("queue delete severity %s, want high", f.Severity)
	}
}

func TestStatelessDestroyIsLow(t *testing.T) {
	p := change(t, "aws_cloudwatch_log_metric_filter", `["delete"]`, `{"name":"x"}`, `null`)
	res := Analyze(p, Options{})
	none(t, res, RuleDestroyStateful)
	if f := one(t, res, RuleDestroy); f.Severity != Low {
		t.Fatalf("severity %s", f.Severity)
	}
}

func TestStatelessReplaceIsLowAndHidesSensitive(t *testing.T) {
	p := change(t, "random_password", `["delete","create"]`, `{"keepers":{"r":"1"},"result":"old"}`,
		`{"keepers":{"r":"2"}}`,
		`"replace_paths":[["result"]]`, `"after_unknown":{"result":true}`,
		`"before_sensitive":{"result":true}`, `"after_sensitive":{"result":true}`)
	f := one(t, Analyze(p, Options{}), RuleReplace)
	if f.Severity != Low {
		t.Fatalf("severity %s", f.Severity)
	}
	if hasDetail(f, "old") || !hasDetail(f, "sensitive value hidden") {
		t.Fatalf("sensitive value leaked or not flagged: %v", f.Details)
	}
}

func TestProtectionRemoved(t *testing.T) {
	p := change(t, "aws_rds_cluster", `["update"]`, `{"deletion_protection":true}`, `{"deletion_protection":false}`)
	f := one(t, Analyze(p, Options{}), RuleProtectionRemoved)
	if f.Severity != High {
		t.Fatalf("severity %s", f.Severity)
	}
}

func TestProtectionWithStringValue(t *testing.T) {
	p := change(t, "google_firestore_database", `["update"]`,
		`{"delete_protection_state":"DELETE_PROTECTION_ENABLED"}`,
		`{"delete_protection_state":"DELETE_PROTECTION_DISABLED"}`)
	one(t, Analyze(p, Options{}), RuleProtectionRemoved)
}

func TestUnguardedCreate(t *testing.T) {
	p := change(t, "aws_dynamodb_table", `["create"]`, `null`, `{"name":"t","deletion_protection_enabled":false}`)
	f := one(t, Analyze(p, Options{}), RuleUnguardedStateful)
	if f.Severity != Low || !hasDetail(f, "deletion_protection_enabled = true") || !hasDetail(f, "pass --tf-dir") {
		t.Fatalf("%+v", f)
	}

	guarded := change(t, "aws_dynamodb_table", `["create"]`, `null`, `{"deletion_protection_enabled":true}`)
	none(t, Analyze(guarded, Options{}), RuleUnguardedStateful)
}

func TestUnguardedRespectsPreventDestroy(t *testing.T) {
	p := change(t, "aws_s3_bucket", `["create"]`, `null`, `{"bucket":"b"}`)
	none(t, Analyze(p, Options{PreventDestroy: map[string]bool{"aws_s3_bucket.this": true}}), RuleUnguardedStateful)

	f := one(t, Analyze(p, Options{PreventDestroy: map[string]bool{}}), RuleUnguardedStateful)
	if hasDetail(f, "pass --tf-dir") {
		t.Fatal("source was read, the hint should be gone")
	}
}

func TestUnguardedSkipsTagOnlyUpdatesAndNonDataKinds(t *testing.T) {
	tags := change(t, "aws_s3_bucket", `["update"]`, `{"bucket":"b","tags":{}}`, `{"bucket":"b","tags":{"a":"b"}}`)
	none(t, Analyze(tags, Options{}), RuleUnguardedStateful)
	eip := change(t, "aws_eip", `["create"]`, `null`, `{"domain":"vpc"}`)
	none(t, Analyze(eip, Options{}), RuleUnguardedStateful)
}

func TestDestroyMentionsMissingPreventDestroy(t *testing.T) {
	p := change(t, "aws_s3_bucket", `["delete"]`, `{"bucket":"b"}`, `null`)
	f := one(t, Analyze(p, Options{PreventDestroy: map[string]bool{"aws_s3_bucket.this": false}}), RuleDestroyStateful)
	if !hasDetail(f, "prevent_destroy = true } is not set") && !hasDetail(f, "is not set in the source") {
		t.Fatalf("details: %v", f.Details)
	}
}

func TestExtraStatefulTypes(t *testing.T) {
	p := change(t, "acme_ledger", `["delete"]`, `{"id":"x"}`, `null`)
	none(t, Analyze(p, Options{}), RuleDestroyStateful)
	res := Analyze(p, Options{ExtraStateful: map[string]Stateful{"acme_ledger": {Kind: "database", Loss: "every journal entry"}}})
	if f := one(t, res, RuleDestroyStateful); f.Title != "Deletes database: every journal entry" {
		t.Fatalf("title %q", f.Title)
	}
}

func TestNoOpAndReadAreIgnored(t *testing.T) {
	p := planOf(t, `"resource_changes":[
		{"address":"aws_s3_bucket.a","mode":"managed","type":"aws_s3_bucket","change":{"actions":["no-op"],"before":{},"after":{}}},
		{"address":"data.aws_iam_policy_document.d","mode":"data","type":"aws_iam_policy_document","change":{"actions":["read"]}}]`)
	res := Analyze(p, Options{})
	if len(res.Findings) != 0 || res.Totals.Total() != 0 {
		t.Fatalf("%+v", res)
	}
}

func TestEveryCatalogEntryIsComplete(t *testing.T) {
	for typ, s := range StatefulTypes {
		if s.Kind == "" || s.Loss == "" {
			t.Errorf("%s: kind and loss are required", typ)
		}
	}
}
