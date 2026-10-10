package triage

import "testing"

const narrow = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::b/*"}]}`

func TestAWSPolicyWidening(t *testing.T) {
	cases := []struct {
		name  string
		after string
		sev   Severity
		want  string
	}{
		{"full admin", `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`, Critical, "full admin"},
		{"service wildcard", `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b"}]}`, High, "every s3 action"},
		{"iam wildcard", `{"Statement":[{"Effect":"Allow","Action":"iam:*","Resource":"arn:aws:iam::1:role/x"}]}`, High, "can grant itself more access (`iam:*`)"},
		{"passrole on star", `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":"*"}]}`, High, "`iam:PassRole` on `*`"},
		{"passrole scoped", `{"Statement":[{"Effect":"Allow","Action":["iam:PassRole"],"Resource":"arn:aws:iam::1:role/app"}]}`, Medium, "`iam:PassRole`"},
		{"not action", `{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`, High, "every action except iam:*"},
		{"partial wildcard on star", `{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"*"}]}`, Medium, "wildcard action `s3:Get*`"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := change(t, "aws_iam_role_policy", `["update"]`, `{"policy":`+policy(narrow)+`}`, `{"policy":`+policy(tc.after)+`}`)
			f := one(t, Analyze(p, Options{}), RuleIAMWidening)
			if f.Severity != tc.sev || !hasDetail(f, tc.want) {
				t.Fatalf("got %s %q %v", f.Severity, f.Title, f.Details)
			}
		})
	}
}

func TestDenyStatementsAreIgnored(t *testing.T) {
	deny := `{"Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}`
	p := change(t, "aws_iam_policy", `["create"]`, `null`, `{"policy":`+policy(deny)+`}`)
	none(t, Analyze(p, Options{}), RuleIAMWidening)
}

func TestAlreadyBroadPolicyIsNotReflagged(t *testing.T) {
	broad := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b"}]}`
	edited := `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::b"},{"Effect":"Allow","Action":"sqs:SendMessage","Resource":"arn:aws:sqs:::q"}]}`
	p := change(t, "aws_iam_policy", `["update"]`, `{"policy":`+policy(broad)+`}`, `{"policy":`+policy(edited)+`}`)
	none(t, Analyze(p, Options{}), RuleIAMWidening)
}

func TestPublicPrincipal(t *testing.T) {
	open := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`
	p := change(t, "aws_s3_bucket_policy", `["create"]`, `null`, `{"policy":`+policy(open)+`}`)
	if f := one(t, Analyze(p, Options{}), RuleIAMWidening); f.Severity != Critical || !hasDetail(f, "any principal") {
		t.Fatalf("%+v", f)
	}

	conditioned := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-1"}}}]}`
	p = change(t, "aws_s3_bucket_policy", `["create"]`, `null`, `{"policy":`+policy(conditioned)+`}`)
	if f := one(t, Analyze(p, Options{}), RuleIAMWidening); f.Severity != High || !hasDetail(f, "Condition") {
		t.Fatalf("%+v", f)
	}
}

func TestTrustPolicyOpenToAnyone(t *testing.T) {
	trust := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
	p := change(t, "aws_iam_role", `["create"]`, `null`, `{"assume_role_policy":`+policy(trust)+`}`)
	if f := one(t, Analyze(p, Options{}), RuleIAMWidening); !hasDetail(f, "role can be assumed by any principal") {
		t.Fatalf("%+v", f)
	}
}

func TestManagedPolicyAttachments(t *testing.T) {
	for arn, sev := range map[string]Severity{
		"arn:aws:iam::aws:policy/AdministratorAccess": Critical,
		"arn:aws:iam::aws:policy/PowerUserAccess":     High,
		"arn:aws:iam::aws:policy/AmazonS3FullAccess":  Medium,
	} {
		p := change(t, "aws_iam_role_policy_attachment", `["create"]`, `null`, `{"policy_arn":"`+arn+`"}`)
		if f := one(t, Analyze(p, Options{}), RuleIAMWidening); f.Severity != sev {
			t.Errorf("%s: got %s want %s", arn, f.Severity, sev)
		}
	}
	custom := change(t, "aws_iam_role_policy_attachment", `["create"]`, `null`, `{"policy_arn":"arn:aws:iam::111122223333:policy/AdministratorAccess"}`)
	none(t, Analyze(custom, Options{}), RuleIAMWidening)
}

func TestSensitivePolicyIsNotRead(t *testing.T) {
	all := `{"Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}`
	p := change(t, "aws_iam_policy", `["create"]`, `null`, `{"policy":`+policy(all)+`}`, `"after_sensitive":{"policy":true}`)
	none(t, Analyze(p, Options{}), RuleIAMWidening)
}

func TestGCPIAM(t *testing.T) {
	p := change(t, "google_storage_bucket_iam_member", `["create"]`, `null`, `{"role":"roles/storage.objectViewer","member":"allUsers"}`)
	if f := one(t, Analyze(p, Options{}), RuleIAMWidening); f.Severity != Critical {
		t.Fatalf("public member severity %s", f.Severity)
	}
	p = change(t, "google_project_iam_member", `["create"]`, `null`, `{"role":"roles/editor","member":"user:a@example.com"}`)
	if f := one(t, Analyze(p, Options{}), RuleIAMWidening); f.Severity != High {
		t.Fatalf("editor severity %s", f.Severity)
	}
	p = change(t, "google_project_iam_member", `["create"]`, `null`, `{"role":"roles/logging.viewer","member":"user:a@example.com"}`)
	none(t, Analyze(p, Options{}), RuleIAMWidening)

	// A binding that gains a member is widening; existing members are not re-flagged.
	p = change(t, "google_project_iam_binding", `["update"]`,
		`{"role":"roles/owner","members":["user:a@example.com"]}`,
		`{"role":"roles/owner","members":["user:a@example.com","user:b@example.com"]}`)
	f := one(t, Analyze(p, Options{}), RuleIAMWidening)
	if !hasDetail(f, "user:b@example.com") || hasDetail(f, "user:a@example.com") {
		t.Fatalf("%+v", f)
	}

	pol := `{"bindings":[{"role":"roles/run.invoker","members":["allUsers"]}]}`
	p = change(t, "google_cloud_run_service_iam_policy", `["create"]`, `null`, `{"policy_data":`+policy(pol)+`}`)
	one(t, Analyze(p, Options{}), RuleIAMWidening)
}

func TestAzureRoleAssignments(t *testing.T) {
	cases := []struct {
		attrs string
		sev   Severity
	}{
		{`{"role_definition_name":"Owner","scope":"/subscriptions/0000"}`, Critical},
		{`{"role_definition_name":"Contributor","scope":"/subscriptions/0000/resourceGroups/rg"}`, High},
		{`{"role_definition_name":"Reader","scope":"/providers/Microsoft.Management/managementGroups/root"}`, Medium},
		{`{"role_definition_id":"/subscriptions/0000/providers/Microsoft.Authorization/roleDefinitions/18d7d88d-d35e-4fb5-a5c3-7773c20a72d9","scope":"/subscriptions/0000"}`, Critical},
	}
	for _, tc := range cases {
		p := change(t, "azurerm_role_assignment", `["create"]`, `null`, tc.attrs)
		if f := one(t, Analyze(p, Options{}), RuleIAMWidening); f.Severity != tc.sev {
			t.Errorf("%s: got %s want %s", tc.attrs, f.Severity, tc.sev)
		}
	}
	reader := change(t, "azurerm_role_assignment", `["create"]`, `null`, `{"role_definition_name":"Reader","scope":"/subscriptions/0/resourceGroups/rg"}`)
	none(t, Analyze(reader, Options{}), RuleIAMWidening)

	custom := change(t, "azurerm_role_definition", `["create"]`, `null`, `{"permissions":[{"actions":["*"]}]}`)
	one(t, Analyze(custom, Options{}), RuleIAMWidening)
}

func TestDeletingAGrantIsNotWidening(t *testing.T) {
	p := change(t, "aws_iam_role_policy_attachment", `["delete"]`, `{"policy_arn":"arn:aws:iam::aws:policy/AdministratorAccess"}`, `null`)
	none(t, Analyze(p, Options{}), RuleIAMWidening)
}
