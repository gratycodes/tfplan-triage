package triage

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

var updateDocs = flag.Bool("update", false, "rewrite docs/rules.md from the rules table")

// docs/rules.md is generated from the tables in catalog.go so the README's
// coverage claims cannot drift from the code.
func TestRulesDocIsCurrent(t *testing.T) {
	var b strings.Builder
	b.WriteString("# Rules table\n\nGenerated from `internal/triage/catalog.go` by `go test ./internal/triage -update`. Do not edit by hand.\n\n")
	b.WriteString("## Stateful resource types\n\nDeleting or replacing these is `critical` (data stores, keys) or `high` (caches, queues, streams, addresses, DNS, registries).\n\n")
	b.WriteString("| Cloud | Type | Kind | Lost on destroy | Deletion protection | Makes it worse when true |\n|---|---|---|---|---|---|\n")
	types := make([]string, 0, len(StatefulTypes))
	for t := range StatefulTypes {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool {
		ci, cj := cloud(types[i]), cloud(types[j])
		if ci != cj {
			return ci < cj
		}
		return types[i] < types[j]
	})
	for _, typ := range types {
		s := StatefulTypes[typ]
		guard := "none"
		if s.GuardAttr != "" {
			on := "true"
			if s.GuardOn != nil {
				on = fmt.Sprintf("%q", s.GuardOn)
			}
			guard = fmt.Sprintf("`%s = %s`", s.GuardAttr, on)
		}
		amps := make([]string, len(s.Amplifiers))
		for i, a := range s.Amplifiers {
			amps[i] = "`" + a + "`"
		}
		fmt.Fprintf(&b, "| %s | `%s` | %s | %s | %s | %s |\n", cloud(typ), typ, s.Kind, s.Loss, guard, strings.Join(amps, ", "))
	}
	b.WriteString("\n## Privileged roles and policies\n\n")
	b.WriteString("- AWS managed policies: " + keys(PrivilegedAWSPolicies) + " (`AdministratorAccess` is critical, `*FullAccess` is medium)\n")
	b.WriteString("- AWS privilege-escalation actions: " + keys(EscalationActions) + "\n")
	b.WriteString("- Google Cloud roles: " + keys(PrivilegedGCPRoles) + "\n")
	b.WriteString("- Azure roles: " + keys(PrivilegedAzureRoles) + "\n")
	b.WriteString("\n## Sensitive ports\n\nWorld-open ingress on these, or on all ports, is critical; other world-open ports are medium.\n\n")
	ports := make([]int, 0, len(SensitivePorts))
	for p := range SensitivePorts {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		fmt.Fprintf(&b, "- %d %s\n", p, SensitivePorts[p])
	}
	got := b.String()
	const path = "../../docs/rules.md"
	if *updateDocs {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil || string(want) != got {
		t.Fatalf("docs/rules.md is stale; run go test ./internal/triage -update (%v)", err)
	}
}

func cloud(typ string) string {
	switch {
	case strings.HasPrefix(typ, "aws_"):
		return "AWS"
	case strings.HasPrefix(typ, "google_"):
		return "Google Cloud"
	case strings.HasPrefix(typ, "azurerm_"):
		return "Azure"
	}
	return "other"
}

func keys[V any](m map[string]V) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, "`"+k+"`")
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
