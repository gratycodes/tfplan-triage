// Package report renders a triage result as a Markdown PR comment, plain
// text for terminals, or JSON for other tools.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/gratycodes/tfplan-triage/internal/triage"
)

// Report bundles what the renderers need.
type Report struct {
	Title  string         `json:"title,omitempty"`
	Result *triage.Result `json:"result"`
	Gate   *triage.Gate   `json:"gate,omitempty"`
}

// Marker starts every Markdown comment so the Action can find and update
// its own comment. Title keeps several plans in one PR apart.
func Marker(title string) string {
	if title == "" {
		title = "default"
	}
	return fmt.Sprintf("<!-- tfplan-triage:%s -->", title)
}

const (
	maxTableRows    = 25
	maxDetailItems  = 60
	maxListedPerBox = 40
)

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func countsLine(c triage.Counts) string {
	if c.Total() == 0 {
		return "no resource changes"
	}
	var parts []string
	if c.Create > 0 {
		parts = append(parts, fmt.Sprintf("+%d", c.Create))
	}
	if c.Update > 0 {
		parts = append(parts, fmt.Sprintf("~%d", c.Update))
	}
	if c.Replace > 0 {
		parts = append(parts, fmt.Sprintf("-/+%d", c.Replace))
	}
	if c.Delete > 0 {
		parts = append(parts, fmt.Sprintf("-%d", c.Delete))
	}
	noun := "changes"
	if c.Total() == 1 {
		noun = "change"
	}
	return fmt.Sprintf("%d %s (%s)", c.Total(), noun, strings.Join(parts, " "))
}

func severityLine(res *triage.Result) string {
	by := res.CountBySeverity()
	var parts []string
	for s := triage.Critical; s >= triage.Medium; s-- {
		if by[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", by[s], s))
		}
	}
	if len(parts) == 0 {
		return "nothing high-risk"
	}
	return strings.Join(parts, ", ")
}

func moduleName(m string) string {
	if m == "" {
		return "(root)"
	}
	return m
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
