package triage

import (
	"path"
)

func (a *analyzer) filter(fs []Finding) []Finding {
	if len(a.opts.Ignore) == 0 {
		return fs
	}
	out := fs[:0]
	for _, f := range fs {
		if a.ignore(f) {
			a.ignored++
			continue
		}
		out = append(out, f)
	}
	return out
}

func (a *analyzer) ignore(f Finding) bool {
	for _, ig := range a.opts.Ignore {
		if !matchAddress(ig.Address, f.Address) {
			continue
		}
		if len(ig.Rules) == 0 {
			return true
		}
		for _, r := range ig.Rules {
			if r == f.Rule {
				return true
			}
		}
	}
	return false
}

// matchAddress matches a glob against an address. "*" matches any run of
// characters including dots and brackets, so "module.sandbox.*" covers the
// whole module.
func matchAddress(glob, addr string) bool {
	if glob == "" {
		return false
	}
	ok, err := path.Match(globToPath(glob), globToPath(addr))
	return err == nil && ok
}

// path.Match stops "*" at "/"; addresses have none, so map "." and the
// bracket characters to safe runes and let "*" span them.
func globToPath(s string) string {
	b := []rune{}
	for _, r := range s {
		switch r {
		case '[':
			b = append(b, '⟦')
		case ']':
			b = append(b, '⟧')
		case '\\':
			b = append(b, '⧵')
		default:
			b = append(b, r)
		}
	}
	return string(b)
}
