package triage

import (
	"encoding/json"
	"testing"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

func TestStripInstanceKeys(t *testing.T) {
	for in, want := range map[string]string{
		`module.db["eu"].aws_db_instance.this[0]`:    "module.db.aws_db_instance.this",
		`aws_s3_bucket.b["a]b"]`:                     "aws_s3_bucket.b",
		`module.a[1].module.b.google_compute_disk.d`: "module.a.module.b.google_compute_disk.d",
		`aws_s3_bucket.plain`:                        "aws_s3_bucket.plain",
	} {
		if got := StripInstanceKeys(in); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
}

func TestIgnore(t *testing.T) {
	p := planOf(t, `"resource_changes":[
		{"address":"module.sandbox.aws_s3_bucket.a","module_address":"module.sandbox","mode":"managed","type":"aws_s3_bucket","change":{"actions":["delete"],"before":{},"after":null}},
		{"address":"module.sandbox.aws_iam_role_policy_attachment.b","module_address":"module.sandbox","mode":"managed","type":"aws_iam_role_policy_attachment","change":{"actions":["create"],"before":null,"after":{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"}}},
		{"address":"aws_s3_bucket.prod","mode":"managed","type":"aws_s3_bucket","change":{"actions":["delete"],"before":{},"after":null}}]`)
	res := Analyze(p, Options{Ignore: []IgnoreRule{{Address: "module.sandbox.*", Rules: []string{RuleDestroyStateful}}}})
	if res.Ignored != 1 || len(res.Findings) != 2 {
		b, _ := json.Marshal(res.Findings)
		t.Fatalf("ignored=%d findings=%s", res.Ignored, b)
	}
	res = Analyze(p, Options{Ignore: []IgnoreRule{{Address: "module.sandbox.*"}}})
	if res.Ignored != 2 || len(res.Findings) != 1 || res.Findings[0].Address != "aws_s3_bucket.prod" {
		t.Fatalf("ignore all rules: %+v", res.Findings)
	}
	res = Analyze(p, Options{Ignore: []IgnoreRule{{Address: `aws_s3_bucket.prod`}}})
	if res.Ignored != 1 {
		t.Fatal("exact address")
	}
}

func TestMatchAddressBrackets(t *testing.T) {
	if !matchAddress(`aws_s3_bucket.b[*]`, `aws_s3_bucket.b["x"]`) {
		t.Error("bracket glob")
	}
	if matchAddress(`aws_s3_bucket.b`, `aws_s3_bucket.bb`) {
		t.Error("prefix should not match")
	}
}

func TestSortingAndModules(t *testing.T) {
	p, err := plan.Load("../../testdata/plans/aws.json")
	if err != nil {
		t.Fatal(err)
	}
	res := Analyze(p, Options{})
	for i := 1; i < len(res.Findings); i++ {
		if res.Findings[i].Severity > res.Findings[i-1].Severity {
			t.Fatalf("not sorted at %d", i)
		}
	}
	if len(res.Modules) != 2 || res.Modules[1].Module != "module.ledger_db" || *res.Modules[1].Highest != Critical {
		t.Fatalf("modules: %+v", res.Modules)
	}
	if res.Modules[1].Counts.Replace != 1 || res.Modules[1].Counts.Delete != 1 {
		t.Fatalf("module counts: %+v", res.Modules[1].Counts)
	}
}

func TestNoiseAndUnflagged(t *testing.T) {
	p := planOf(t, `"resource_changes":[
		{"address":"aws_sqs_queue.q","mode":"managed","type":"aws_lambda_function","change":{"actions":["update"],"before":{"tags":{}},"after":{"tags":{"a":"b"}}}},
		{"address":"google_pubsub_topic.t","mode":"managed","type":"google_pubsub_topic","change":{"actions":["update"],"before":{"labels":{}},"after":{"labels":{"a":"b"}}}},
		{"address":"aws_lambda_function.f","mode":"managed","type":"aws_lambda_function","change":{"actions":["update"],"before":{"memory_size":128},"after":{"memory_size":256}}},
		{"address":"aws_lambda_function.moved","previous_address":"aws_lambda_function.old","mode":"managed","type":"aws_lambda_function","change":{"actions":["no-op"],"before":{},"after":{}}},
		{"address":"aws_lambda_function.gone","mode":"managed","type":"aws_lambda_function","change":{"actions":["forget"],"before":{},"after":null}}]`)
	res := Analyze(p, Options{})
	if len(res.Noise) != 2 || res.Noise[0].Reason != "labels only" || res.Noise[1].Reason != "tags only" {
		t.Fatalf("noise %+v", res.Noise)
	}
	if len(res.Unflagged) != 3 {
		t.Fatalf("unflagged %+v", res.Unflagged)
	}
	if res.Totals.Update != 3 || res.Totals.Total() != 3 {
		t.Fatalf("totals %+v", res.Totals)
	}
}

func TestSeverityJSON(t *testing.T) {
	b, _ := json.Marshal(High)
	if string(b) != `"high"` {
		t.Fatal(string(b))
	}
	var s Severity
	if err := json.Unmarshal([]byte(`"critical"`), &s); err != nil || s != Critical {
		t.Fatal(s, err)
	}
	if err := json.Unmarshal([]byte(`"severe"`), &s); err == nil {
		t.Fatal("want error")
	}
	if none, _ := ParseSeverity("none"); none <= Critical {
		t.Fatal("none must be above critical")
	}
}
