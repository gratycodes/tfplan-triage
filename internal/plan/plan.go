// Package plan reads the JSON representation of a Terraform or OpenTofu
// plan (`terraform show -json plan.out`) and exposes the parts a reviewer
// cares about: what each resource change does, which attributes change,
// which ones force replacement, and which values are sensitive.
//
// Only the fields this tool needs are decoded. The format is documented at
// https://developer.hashicorp.com/terraform/internals/json-format and is
// the same for OpenTofu.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Plan is the subset of the plan JSON this tool reads.
type Plan struct {
	FormatVersion    string           `json:"format_version"`
	TerraformVersion string           `json:"terraform_version"`
	ResourceChanges  []ResourceChange `json:"resource_changes"`
	ResourceDrift    []ResourceChange `json:"resource_drift"`
	Configuration    Configuration    `json:"configuration"`
	Errored          bool             `json:"errored"`
}

// ResourceChange is one entry of resource_changes or resource_drift.
type ResourceChange struct {
	Address         string `json:"address"`
	PreviousAddress string `json:"previous_address"`
	ModuleAddress   string `json:"module_address"`
	Mode            string `json:"mode"`
	Type            string `json:"type"`
	Name            string `json:"name"`
	ProviderName    string `json:"provider_name"`
	ActionReason    string `json:"action_reason"`
	Change          Change `json:"change"`
}

// Change is the before/after pair of a resource change.
type Change struct {
	Actions         []string  `json:"actions"`
	Before          any       `json:"before"`
	After           any       `json:"after"`
	AfterUnknown    any       `json:"after_unknown"`
	BeforeSensitive any       `json:"before_sensitive"`
	AfterSensitive  any       `json:"after_sensitive"`
	ReplacePaths    [][]any   `json:"replace_paths"`
	Importing       *struct{} `json:"importing"`
}

// Configuration holds the module tree, used to find local module sources.
type Configuration struct {
	RootModule ConfigModule `json:"root_module"`
}

// ConfigModule is one module in the configuration tree.
type ConfigModule struct {
	ModuleCalls map[string]ModuleCall `json:"module_calls"`
}

// ModuleCall is a `module` block.
type ModuleCall struct {
	Source string       `json:"source"`
	Module ConfigModule `json:"module"`
}

// Action is the normalised kind of a resource change.
type Action string

// Actions, ordered roughly by how much attention they need.
const (
	NoOp    Action = "no-op"
	Read    Action = "read"
	Create  Action = "create"
	Update  Action = "update"
	Replace Action = "replace"
	Delete  Action = "delete"
	Forget  Action = "forget"
)

// Load reads a plan JSON file; "-" reads stdin.
func Load(path string) (*Plan, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return Decode(r)
}

// Decode parses plan JSON and rejects input that is clearly not a plan,
// for example the output of `terraform show -json` on a state file.
func Decode(r io.Reader) (*Plan, error) {
	var p Plan
	dec := json.NewDecoder(r)
	dec.UseNumber()
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("decode plan JSON: %w", err)
	}
	if p.FormatVersion == "" {
		return nil, errors.New("not a plan JSON document (no format_version); use `terraform show -json plan.out`")
	}
	if major := strings.SplitN(p.FormatVersion, ".", 2)[0]; major != "1" {
		return nil, fmt.Errorf("unsupported plan format_version %q (want 1.x)", p.FormatVersion)
	}
	return &p, nil
}

// Action returns the normalised action of the change.
func (rc *ResourceChange) Action() Action {
	a := rc.Change.Actions
	switch {
	case len(a) == 2:
		return Replace
	case len(a) == 1:
		switch a[0] {
		case "create":
			return Create
		case "update":
			return Update
		case "delete":
			return Delete
		case "read":
			return Read
		case "forget":
			return Forget
		}
	}
	return NoOp
}

// CreateBeforeDestroy reports whether a replacement creates the new object
// first (lifecycle create_before_destroy).
func (rc *ResourceChange) CreateBeforeDestroy() bool {
	a := rc.Change.Actions
	return len(a) == 2 && a[0] == "create"
}

// Moved reports whether the resource was renamed with a moved block.
func (rc *ResourceChange) Moved() bool { return rc.PreviousAddress != "" }

// Imported reports whether the change imports an existing object.
func (rc *ResourceChange) Imported() bool { return rc.Change.Importing != nil }

// Module returns the module address, or "" for the root module.
func (rc *ResourceChange) Module() string { return rc.ModuleAddress }

// BeforeMap returns the prior attributes as a map (nil when absent).
func (rc *ResourceChange) BeforeMap() map[string]any { return asMap(rc.Change.Before) }

// AfterMap returns the planned attributes as a map (nil when absent).
func (rc *ResourceChange) AfterMap() map[string]any { return asMap(rc.Change.After) }

// AfterUnknown reports whether a top-level attribute, or any part of it,
// is only known after apply.
func (rc *ResourceChange) AfterUnknown(attr string) bool {
	m := asMap(rc.Change.AfterUnknown)
	if m == nil {
		return false
	}
	return containsTrue(m[attr])
}

// Sensitive reports whether a top-level attribute is marked sensitive on
// either side of the change. Callers must not print such values.
func (rc *ResourceChange) Sensitive(attr string) bool {
	return marked(rc.Change.BeforeSensitive, attr) || marked(rc.Change.AfterSensitive, attr)
}

func marked(mask any, attr string) bool {
	switch m := mask.(type) {
	case bool:
		return m
	case map[string]any:
		v, ok := m[attr]
		if !ok {
			return false
		}
		if b, isBool := v.(bool); isBool {
			return b
		}
		// A nested mask means some part of the value is sensitive.
		return containsTrue(v)
	}
	return false
}

func containsTrue(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case map[string]any:
		for _, e := range x {
			if containsTrue(e) {
				return true
			}
		}
	case []any:
		for _, e := range x {
			if containsTrue(e) {
				return true
			}
		}
	}
	return false
}

// ChangedAttributes lists the top-level attributes whose value differs
// between before and after, plus those that become unknown. Sorted.
func (rc *ResourceChange) ChangedAttributes() []string {
	before, after := rc.BeforeMap(), rc.AfterMap()
	if before == nil || after == nil {
		return nil
	}
	seen := map[string]bool{}
	for k, bv := range before {
		if !Equal(bv, after[k]) {
			seen[k] = true
		}
	}
	for k, av := range after {
		if !Equal(before[k], av) {
			seen[k] = true
		}
	}
	for k := range asMap(rc.Change.AfterUnknown) {
		if rc.AfterUnknown(k) {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ReplacePaths renders replace_paths as dotted attribute paths, e.g.
// "settings.0.tier". Sorted and de-duplicated.
func (rc *ResourceChange) ReplacePaths() []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range rc.Change.ReplacePaths {
		parts := make([]string, 0, len(p))
		for _, step := range p {
			parts = append(parts, fmt.Sprint(step))
		}
		s := strings.Join(parts, ".")
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// Equal compares two decoded JSON values. Numbers decoded with UseNumber
// compare by their text, which is what Terraform writes.
func Equal(a, b any) bool { return reflect.DeepEqual(a, b) }

func asMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

// Str returns a string attribute, "" when absent or not a string.
func Str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// Bool returns a bool attribute and whether it was set.
func Bool(m map[string]any, key string) (val, ok bool) {
	b, ok := m[key].(bool)
	return b, ok
}

// List returns a list attribute (lists and sets both decode to []any).
func List(m map[string]any, key string) []any {
	l, _ := m[key].([]any)
	return l
}

// Strings returns a list attribute as strings, skipping non-strings.
func Strings(m map[string]any, key string) []string {
	var out []string
	for _, v := range List(m, key) {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Blocks returns a nested block attribute as a list of maps.
func Blocks(m map[string]any, key string) []map[string]any {
	var out []map[string]any
	for _, v := range List(m, key) {
		if b, ok := v.(map[string]any); ok {
			out = append(out, b)
		}
	}
	return out
}
