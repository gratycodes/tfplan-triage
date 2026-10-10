package report

import (
	"fmt"
	"io"
	"strings"
)

// Text renders a compact terminal report.
func Text(w io.Writer, r Report) error {
	res := r.Result
	var b strings.Builder
	fmt.Fprintf(&b, "%s · %s", severityLine(res), countsLine(res.Totals))
	if res.Drifted > 0 {
		fmt.Fprintf(&b, " · %d drifted", res.Drifted)
	}
	b.WriteString("\n")
	if res.Errored {
		b.WriteString("warning: the plan errored, so this list may be incomplete\n")
	}
	if len(res.Findings) > 0 {
		b.WriteString("\n")
	}
	for _, f := range res.Findings {
		mark := ""
		if f.Blocking {
			mark = "  [blocking"
			if f.NeedsLabel != "" {
				mark += ", needs " + f.NeedsLabel
			}
			mark += "]"
		} else if f.ApprovedBy != "" {
			mark = "  [approved by " + f.ApprovedBy + "]"
		}
		fmt.Fprintf(&b, "%-8s %s%s\n         %s\n", strings.ToUpper(f.Severity.String()), f.Address, mark, f.Title)
		for _, d := range f.Details {
			fmt.Fprintf(&b, "         - %s\n", strings.ReplaceAll(d, "`", ""))
		}
	}
	for _, g := range res.Noise {
		fmt.Fprintf(&b, "\nupdates to %s: %s\n", g.Reason, plural(len(g.Addresses), "resource", "resources"))
	}
	if r.Gate != nil && r.Gate.FailOn != "none" && r.Gate.FailOn != "" {
		b.WriteString("\n")
		switch {
		case r.Gate.Blocked && len(r.Gate.MissingLabels) > 0:
			fmt.Fprintf(&b, "FAIL: %d blocking at %s or above; after review, add label %s\n", r.Gate.Blocking, r.Gate.FailOn, strings.Join(r.Gate.MissingLabels, " and "))
		case r.Gate.Blocked:
			fmt.Fprintf(&b, "FAIL: %d blocking at %s or above\n", r.Gate.Blocking, r.Gate.FailOn)
		default:
			fmt.Fprintf(&b, "PASS: nothing unapproved at %s or above\n", r.Gate.FailOn)
		}
	}
	_, err := io.WriteString(w, strings.ReplaceAll(b.String(), "`", ""))
	return err
}
