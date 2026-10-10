package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/triage"
)

// Markdown renders the PR comment. Findings at medium or above go in the
// table; everything else is collapsed.
func Markdown(w io.Writer, r Report) error {
	res := r.Result
	var b strings.Builder
	b.WriteString(Marker(r.Title) + "\n")
	heading := "Terraform plan triage"
	if r.Title != "" {
		heading += ": " + r.Title
	}
	fmt.Fprintf(&b, "### %s\n\n", heading)
	fmt.Fprintf(&b, "**%s** · %s", severityLine(res), countsLine(res.Totals))
	if res.Drifted > 0 {
		fmt.Fprintf(&b, " · %s outside Terraform", plural(res.Drifted, "resource changed", "resources changed"))
	}
	b.WriteString("\n\n")
	if res.Errored {
		b.WriteString("> [!WARNING]\n> The plan errored, so this list may be incomplete.\n\n")
	}
	writeGate(&b, r.Gate)

	var top, rest []triage.Finding
	for _, f := range res.Findings {
		if f.Severity >= triage.Medium {
			top = append(top, f)
		} else {
			rest = append(rest, f)
		}
	}
	if len(top) > 0 {
		b.WriteString("| Severity | What happens | Resource |\n|---|---|---|\n")
		for i, f := range top {
			if i == maxTableRows {
				fmt.Fprintf(&b, "| | …and %d more, see below | |\n", len(top)-maxTableRows)
				break
			}
			sev := f.Severity.String()
			if f.Severity >= triage.High {
				sev = "**" + sev + "**"
			}
			if f.Blocking {
				sev += ", blocking"
			}
			res := "`" + f.Address + "`"
			fmt.Fprintf(&b, "| %s | %s | %s |\n", sev, cell(f.Title), res)
		}
		b.WriteString("\n")
		writeDetails(&b, top)
	} else {
		b.WriteString("No destructive, IAM, network-exposure or drift findings at medium or above.\n\n")
	}

	if len(res.Modules) > 1 {
		b.WriteString("<details><summary>By module</summary>\n\n")
		b.WriteString("| Module | + | ~ | -/+ | - | Findings | Highest |\n|---|--:|--:|--:|--:|--:|---|\n")
		for _, m := range res.Modules {
			hi := ""
			if m.Highest != nil {
				hi = m.Highest.String()
			}
			fmt.Fprintf(&b, "| `%s` | %d | %d | %d | %d | %d | %s |\n", moduleName(m.Module),
				m.Counts.Create, m.Counts.Update, m.Counts.Replace, m.Counts.Delete, m.Findings, hi)
		}
		b.WriteString("\n</details>\n\n")
	}

	writeQuiet(&b, rest, res)

	b.WriteString("<sub>tfplan-triage")
	if res.TerraformVersion != "" {
		fmt.Fprintf(&b, " · plan from Terraform/OpenTofu %s", res.TerraformVersion)
	}
	if res.Ignored > 0 {
		fmt.Fprintf(&b, " · %s ignored by config", plural(res.Ignored, "finding", "findings"))
	}
	b.WriteString(" · rule-based, not a substitute for reading the plan</sub>\n")
	_, err := io.WriteString(w, b.String())
	return err
}

func writeGate(b *strings.Builder, g *triage.Gate) {
	if g == nil || g.FailOn == "none" || g.FailOn == "" {
		return
	}
	switch {
	case g.Blocked && len(g.MissingLabels) > 0:
		fmt.Fprintf(b, "> [!CAUTION]\n> **Check failed:** %s at `%s` or above need approval. After review, add %s to the PR.\n\n",
			plural(g.Blocking, "finding", "findings"), g.FailOn, labelList(g.MissingLabels, "and"))
	case g.Blocked:
		fmt.Fprintf(b, "> [!CAUTION]\n> **Check failed:** %s at `%s` or above, and no approval label is configured for them.\n\n",
			plural(g.Blocking, "finding", "findings"), g.FailOn)
	case g.Approved > 0:
		fmt.Fprintf(b, "> [!NOTE]\n> **Check passed:** %s at `%s` or above approved by %s.\n\n",
			plural(g.Approved, "finding", "findings"), g.FailOn, labelList(g.ApprovedLabels, "and"))
	default:
		fmt.Fprintf(b, "> **Check passed:** nothing at `%s` or above.\n\n", g.FailOn)
	}
}

func labelList(ls []string, conj string) string {
	q := make([]string, len(ls))
	for i, l := range ls {
		q[i] = "`" + l + "`"
	}
	if len(q) <= 1 {
		return strings.Join(q, "")
	}
	return strings.Join(q[:len(q)-1], ", ") + " " + conj + " " + q[len(q)-1]
}

func writeDetails(b *strings.Builder, fs []triage.Finding) {
	b.WriteString("<details><summary>Why these were flagged</summary>\n\n")
	for i, f := range fs {
		if i == maxDetailItems {
			fmt.Fprintf(b, "…%d more in the JSON report.\n\n", len(fs)-maxDetailItems)
			break
		}
		meta := []string{f.Severity.String(), f.Rule}
		if f.Blocking && f.NeedsLabel != "" {
			meta = append(meta, "needs `"+f.NeedsLabel+"`")
		} else if f.Blocking {
			meta = append(meta, "blocking")
		}
		if f.ApprovedBy != "" {
			meta = append(meta, "approved by `"+f.ApprovedBy+"`")
		}
		fmt.Fprintf(b, "**`%s`** (%s)\n", f.Address, strings.Join(meta, ", "))
		fmt.Fprintf(b, "- %s\n", f.Title)
		for _, d := range f.Details {
			fmt.Fprintf(b, "- %s\n", d)
		}
		b.WriteString("\n")
	}
	b.WriteString("</details>\n\n")
}

func writeQuiet(b *strings.Builder, rest []triage.Finding, res *triage.Result) {
	n := len(rest) + len(res.Unflagged)
	for _, g := range res.Noise {
		n += len(g.Addresses)
	}
	if n == 0 {
		return
	}
	fmt.Fprintf(b, "<details><summary>%s</summary>\n\n", plural(n, "lower-risk change", "lower-risk changes"))
	if len(rest) > 0 {
		b.WriteString("**Low / info**\n")
		for i, f := range rest {
			if i == maxListedPerBox {
				fmt.Fprintf(b, "- …%d more\n", len(rest)-maxListedPerBox)
				break
			}
			fmt.Fprintf(b, "- `%s`: %s\n", f.Address, f.Title)
		}
		b.WriteString("\n")
	}
	for _, g := range res.Noise {
		fmt.Fprintf(b, "**Updates to %s** (%d)\n", g.Reason, len(g.Addresses))
		writeAddrs(b, g.Addresses)
	}
	if len(res.Unflagged) > 0 {
		fmt.Fprintf(b, "**Other changes** (%d)\n", len(res.Unflagged))
		for i, c := range res.Unflagged {
			if i == maxListedPerBox {
				fmt.Fprintf(b, "- …%d more\n", len(res.Unflagged)-maxListedPerBox)
				break
			}
			note := ""
			if c.Note != "" {
				note = " (" + c.Note + ")"
			}
			fmt.Fprintf(b, "- %s `%s`%s\n", c.Action, c.Address, note)
		}
		b.WriteString("\n")
	}
	b.WriteString("</details>\n\n")
}

func writeAddrs(b *strings.Builder, addrs []string) {
	shown := addrs
	if len(shown) > maxListedPerBox {
		shown = shown[:maxListedPerBox]
	}
	q := make([]string, len(shown))
	for i, a := range shown {
		q[i] = "`" + a + "`"
	}
	b.WriteString(strings.Join(q, ", "))
	if len(addrs) > len(shown) {
		fmt.Fprintf(b, " …and %d more", len(addrs)-len(shown))
	}
	b.WriteString("\n\n")
}

// cell escapes a value for a Markdown table cell.
func cell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}
