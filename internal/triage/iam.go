package triage

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/plan"
)

// grant is one fact about what a policy allows. Facts are compared as
// strings between before and after; only new facts are reported, so a
// policy that was already broad is not re-flagged on every change.
type grant struct {
	fact string
	sev  Severity
}

type grantSet map[string]Severity

func (g grantSet) add(sev Severity, format string, args ...any) {
	f := fmt.Sprintf(format, args...)
	if cur, ok := g[f]; !ok || sev > cur {
		g[f] = sev
	}
}

// awsPolicyAttrs maps resource types to attributes holding IAM policy JSON.
var awsPolicyAttrs = map[string][]string{
	"aws_iam_policy":                   {"policy"},
	"aws_iam_role_policy":              {"policy"},
	"aws_iam_user_policy":              {"policy"},
	"aws_iam_group_policy":             {"policy"},
	"aws_iam_role":                     {"assume_role_policy"},
	"aws_s3_bucket_policy":             {"policy"},
	"aws_sqs_queue_policy":             {"policy"},
	"aws_sns_topic_policy":             {"policy"},
	"aws_kms_key":                      {"policy"},
	"aws_ecr_repository_policy":        {"policy"},
	"aws_secretsmanager_secret_policy": {"policy"},
	"aws_glacier_vault":                {"access_policy"},
}

var awsAttachmentTypes = map[string]bool{
	"aws_iam_role_policy_attachment":  true,
	"aws_iam_user_policy_attachment":  true,
	"aws_iam_group_policy_attachment": true,
	"aws_iam_policy_attachment":       true,
}

var (
	gcpIAMMember  = regexp.MustCompile(`^google_.+_iam_member$`)
	gcpIAMBinding = regexp.MustCompile(`^google_.+_iam_binding$`)
	gcpIAMPolicy  = regexp.MustCompile(`^google_.+_iam_policy$`)
)

// Built-in Azure role definition GUIDs, for role_definition_id.
var azureRoleIDs = map[string]string{
	"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
	"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
	"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator",
	"f58310d9-a9f6-439a-9e8d-f62e7b41a168": "Role Based Access Control Administrator",
}

func (a *analyzer) iam(rc *plan.ResourceChange) []Finding {
	act := rc.Action()
	if act != plan.Create && act != plan.Update && act != plan.Replace {
		return nil
	}
	before := a.grants(rc, rc.BeforeMap())
	after := a.grants(rc, rc.AfterMap())
	var added []grant
	for f, sev := range after {
		if old, ok := before[f]; !ok || sev > old {
			added = append(added, grant{f, sev})
		}
	}
	if len(added) == 0 {
		return nil
	}
	sort.Slice(added, func(i, j int) bool {
		if added[i].sev != added[j].sev {
			return added[i].sev > added[j].sev
		}
		return added[i].fact < added[j].fact
	})
	verb := "Widens"
	if act == plan.Create {
		verb = "Grants"
	}
	d := make([]string, len(added))
	for i, g := range added {
		d[i] = g.fact
	}
	title := fmt.Sprintf("%s access: %s", verb, added[0].fact)
	if len(added) > 1 {
		title += fmt.Sprintf(" (+%d more)", len(added)-1)
	}
	return []Finding{newFinding(rc, RuleIAMWidening, added[0].sev, title, d[1:]...)}
}

// grants extracts the risky facts of one side of a change.
func (a *analyzer) grants(rc *plan.ResourceChange, attrs map[string]any) grantSet {
	g := grantSet{}
	if attrs == nil {
		return g
	}
	t := rc.Type
	if attrsWithPolicy, ok := awsPolicyAttrs[t]; ok {
		for _, attr := range attrsWithPolicy {
			if rc.Sensitive(attr) {
				continue
			}
			awsPolicyGrants(g, plan.Str(attrs, attr), attr == "assume_role_policy")
		}
	}
	if t == "aws_iam_role" {
		for _, b := range plan.Blocks(attrs, "inline_policy") {
			awsPolicyGrants(g, plan.Str(b, "policy"), false)
		}
		for _, arn := range plan.Strings(attrs, "managed_policy_arns") {
			awsManagedPolicy(g, arn)
		}
	}
	if awsAttachmentTypes[t] {
		awsManagedPolicy(g, plan.Str(attrs, "policy_arn"))
	}
	if t == "aws_lambda_permission" && plan.Str(attrs, "principal") == "*" {
		g.add(Critical, "lambda can be invoked by any AWS principal (`principal = \"*\"`)")
	}
	switch {
	case gcpIAMMember.MatchString(t):
		gcpGrant(g, plan.Str(attrs, "role"), plan.Str(attrs, "member"), t)
	case gcpIAMBinding.MatchString(t):
		for _, m := range plan.Strings(attrs, "members") {
			gcpGrant(g, plan.Str(attrs, "role"), m, t)
		}
	case gcpIAMPolicy.MatchString(t):
		var doc struct {
			Bindings []struct {
				Role    string   `json:"role"`
				Members []string `json:"members"`
			} `json:"bindings"`
		}
		if json.Unmarshal([]byte(plan.Str(attrs, "policy_data")), &doc) == nil {
			for _, b := range doc.Bindings {
				for _, m := range b.Members {
					gcpGrant(g, b.Role, m, t)
				}
			}
		}
	}
	if t == "azurerm_role_assignment" {
		azureAssignment(g, attrs)
	}
	if t == "azurerm_role_definition" {
		for _, p := range plan.Blocks(attrs, "permissions") {
			for _, act := range plan.Strings(p, "actions") {
				if act == "*" {
					g.add(High, "custom role allows every action (`actions = [\"*\"]`)")
				}
			}
		}
	}
	return g
}

type policyDoc struct {
	Statement statements `json:"Statement"`
}

type statement struct {
	Effect    string          `json:"Effect"`
	Action    strOrList       `json:"Action"`
	NotAction strOrList       `json:"NotAction"`
	Resource  strOrList       `json:"Resource"`
	Principal json.RawMessage `json:"Principal"`
	Condition json.RawMessage `json:"Condition"`
}

// statements accepts a single statement object or a list.
type statements []statement

func (s *statements) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '{' {
		var one statement
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = statements{one}
		return nil
	}
	var many []statement
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// strOrList accepts "x" or ["x", "y"].
type strOrList []string

func (s *strOrList) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = strOrList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

func awsPolicyGrants(g grantSet, doc string, trust bool) {
	if doc == "" {
		return
	}
	var p policyDoc
	if err := json.Unmarshal([]byte(doc), &p); err != nil {
		return
	}
	for _, st := range p.Statement {
		if !strings.EqualFold(st.Effect, "Allow") {
			continue
		}
		if publicPrincipal(st.Principal) {
			what := "resource policy allows any principal (`Principal: \"*\"`)"
			if trust {
				what = "role can be assumed by any principal (`Principal: \"*\"`)"
			}
			if len(st.Condition) > 0 && string(st.Condition) != "null" && string(st.Condition) != "{}" {
				g.add(High, "%s, narrowed only by a Condition", what)
			} else {
				g.add(Critical, "%s", what)
			}
		}
		if trust {
			continue
		}
		allResources := false
		for _, r := range st.Resource {
			if r == "*" {
				allResources = true
			}
		}
		if len(st.NotAction) > 0 {
			g.add(High, "allows every action except %s (`NotAction`)", strings.Join(st.NotAction, ", "))
		}
		for _, act := range st.Action {
			la := strings.ToLower(act)
			switch {
			case act == "*" && allResources:
				g.add(Critical, "full admin: `Action \"*\"` on `Resource \"*\"`")
			case act == "*":
				g.add(High, "every action (`Action \"*\"`)")
			case strings.HasSuffix(act, ":*"):
				svc := strings.TrimSuffix(act, ":*")
				sev := High
				if allResources {
					g.add(sev, "every %s action on every resource (`%s` on `*`)", svc, act)
				} else {
					g.add(sev, "every %s action (`%s`)", svc, act)
				}
				if svc == "iam" || svc == "sts" {
					g.add(High, "can grant itself more access (`%s`)", act)
				}
			case EscalationActions[la]:
				if allResources {
					g.add(High, "can grant itself more access (`%s` on `*`)", act)
				} else {
					g.add(Medium, "can grant itself more access (`%s`)", act)
				}
			case strings.Contains(act, "*") && allResources:
				g.add(Medium, "wildcard action `%s` on every resource", act)
			}
		}
	}
}

func publicPrincipal(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s == "*"
	}
	var m map[string]strOrList
	if json.Unmarshal(raw, &m) == nil {
		for _, v := range m {
			for _, p := range v {
				if p == "*" {
					return true
				}
			}
		}
	}
	return false
}

func awsManagedPolicy(g grantSet, arn string) {
	if arn == "" {
		return
	}
	name := arn[strings.LastIndex(arn, "/")+1:]
	awsManaged := strings.HasPrefix(arn, "arn:aws:iam::aws:policy/")
	switch {
	case awsManaged && PrivilegedAWSPolicies[name]:
		sev := High
		if name == "AdministratorAccess" {
			sev = Critical
		}
		g.add(sev, "attaches AWS managed `%s`", name)
	case awsManaged && strings.HasSuffix(name, "FullAccess"):
		g.add(Medium, "attaches AWS managed `%s`", name)
	}
}

func gcpGrant(g grantSet, role, member, t string) {
	if role == "" || member == "" {
		return
	}
	if member == "allUsers" || member == "allAuthenticatedUsers" {
		g.add(Critical, "`%s` granted to `%s` (public) via %s", role, member, t)
		return
	}
	if PrivilegedGCPRoles[role] {
		g.add(High, "`%s` granted to `%s`", role, member)
	}
}

var subscriptionScope = regexp.MustCompile(`^/subscriptions/[^/]+/?$`)

func azureAssignment(g grantSet, attrs map[string]any) {
	role := plan.Str(attrs, "role_definition_name")
	if role == "" {
		id := plan.Str(attrs, "role_definition_id")
		role = azureRoleIDs[strings.ToLower(id[strings.LastIndex(id, "/")+1:])]
	}
	scope := plan.Str(attrs, "scope")
	broad := subscriptionScope.MatchString(scope) || strings.Contains(scope, "/providers/Microsoft.Management/managementGroups/")
	where := "a resource-group or resource scope"
	if broad {
		where = "subscription or management-group scope"
	}
	switch {
	case PrivilegedAzureRoles[role] && broad:
		g.add(Critical, "`%s` at %s (`%s`)", role, where, scope)
	case PrivilegedAzureRoles[role]:
		g.add(High, "`%s` at %s", role, where)
	case broad && role != "":
		g.add(Medium, "`%s` at %s (`%s`)", role, where, scope)
	}
}
