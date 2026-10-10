package triage

import "testing"

func drifted(t *testing.T, typ, actions, before, after string) *Result {
	t.Helper()
	p := planOf(t, `"resource_drift":[{"address":"`+typ+`.this","mode":"managed","type":"`+typ+`","name":"this",
		"change":{"actions":`+actions+`,"before":`+before+`,"after":`+after+`}}]`)
	return Analyze(p, Options{})
}

func TestDrift(t *testing.T) {
	res := drifted(t, "aws_db_instance", `["delete"]`, `{"identifier":"db"}`, `null`)
	if f := one(t, res, RuleDrift); f.Severity != High || !hasDetail(f, "new, empty one") {
		t.Fatalf("%+v", f)
	}
	if res.Drifted != 1 {
		t.Fatalf("drifted %d", res.Drifted)
	}

	res = drifted(t, "aws_lambda_function", `["delete"]`, `{"function_name":"f"}`, `null`)
	if f := one(t, res, RuleDrift); f.Severity != Medium {
		t.Fatalf("%+v", f)
	}

	res = drifted(t, "aws_db_instance", `["update"]`, `{"instance_class":"db.t4g.medium","deletion_protection":true}`, `{"instance_class":"db.r6g.large","deletion_protection":false}`)
	f := one(t, res, RuleDrift)
	if f.Severity != High || !hasDetail(f, "`deletion_protection`, `instance_class`") || !hasDetail(f, "turned off by hand") {
		t.Fatalf("%+v", f)
	}

	res = drifted(t, "aws_instance", `["update"]`, `{"tags":{}}`, `{"tags":{"owner":"x"}}`)
	if f := one(t, res, RuleDrift); f.Severity != Low {
		t.Fatalf("tag drift %+v", f)
	}

	res = drifted(t, "aws_instance", `["update"]`, `{"a":1}`, `{"a":1}`)
	none(t, res, RuleDrift)
}

func TestLimit(t *testing.T) {
	got := limit([]string{"a", "b", "c"}, 2)
	if len(got) != 3 || got[2] != "+1 more" {
		t.Fatal(got)
	}
}
