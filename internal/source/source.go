// Package source reads lifecycle.prevent_destroy from Terraform source.
//
// The plan JSON does not include lifecycle settings, so a reviewer cannot
// tell from the plan alone whether a database is protected by
// prevent_destroy. This package parses the .tf files of the root module
// and of local modules (source = "./..." or "../...") and returns the
// setting per resource address.
package source

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
)

// PreventDestroy maps "module.a.module.b.type.name" (no instance keys) to
// the literal prevent_destroy value. Resources whose value is not a
// literal (for example a variable) are left out, so callers treat them as
// unknown. Remote modules (registry, git) are not read.
func PreventDestroy(dir string) (map[string]bool, error) {
	out := map[string]bool{}
	if err := readModule(dir, "", out, map[string]bool{}); err != nil {
		return nil, err
	}
	return out, nil
}

func readModule(dir, prefix string, out map[string]bool, seen map[string]bool) error {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if seen[abs+"|"+prefix] {
		return nil
	}
	seen[abs+"|"+prefix] = true
	files, err := filepath.Glob(filepath.Join(dir, "*.tf"))
	if err != nil {
		return err
	}
	if len(files) == 0 && prefix == "" {
		return fmt.Errorf("no .tf files in %s", dir)
	}
	sort.Strings(files)
	for _, f := range files {
		src, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		file, diags := hclsyntax.ParseConfig(src, f, hcl.InitialPos)
		if diags.HasErrors() {
			return fmt.Errorf("parse %s: %s", f, diags.Error())
		}
		body, ok := file.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}
		for _, b := range body.Blocks {
			switch {
			case b.Type == "resource" && len(b.Labels) == 2:
				addr := prefix + b.Labels[0] + "." + b.Labels[1]
				if v, known := preventDestroy(b.Body); known {
					out[addr] = v
				}
			case b.Type == "module" && len(b.Labels) == 1:
				srcAttr, ok := b.Body.Attributes["source"]
				if !ok {
					continue
				}
				val, diags := srcAttr.Expr.Value(nil)
				if diags.HasErrors() || !val.Type().Equals(cty.String) {
					continue
				}
				s := val.AsString()
				if !strings.HasPrefix(s, "./") && !strings.HasPrefix(s, "../") {
					continue
				}
				if err := readModule(filepath.Join(dir, s), prefix+"module."+b.Labels[0]+".", out, seen); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// preventDestroy returns the literal value, (false, true) when there is no
// lifecycle setting, and (false, false) when it is not a literal.
func preventDestroy(body *hclsyntax.Body) (value, known bool) {
	for _, b := range body.Blocks {
		if b.Type != "lifecycle" {
			continue
		}
		attr, ok := b.Body.Attributes["prevent_destroy"]
		if !ok {
			continue
		}
		v, diags := attr.Expr.Value(nil)
		if diags.HasErrors() || !v.IsKnown() || v.IsNull() || !v.Type().Equals(cty.Bool) {
			return false, false
		}
		return v.True(), true
	}
	return false, true
}
