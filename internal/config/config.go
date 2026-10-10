// Package config loads .tfplan-triage.yml.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/gratycodes/tfplan-triage/internal/triage"
)

// DefaultPath is read when it exists and no --config is given.
const DefaultPath = ".tfplan-triage.yml"

// Config is the policy file. Every field is optional.
type Config struct {
	// FailOn is the lowest severity that fails the check
	// (info, low, medium, high, critical or none).
	FailOn string `yaml:"fail_on"`
	// Approvals map PR labels to the findings they approve.
	Approvals []triage.Approval `yaml:"approvals"`
	// Ignore suppresses findings by address glob and rule.
	Ignore []triage.IgnoreRule `yaml:"ignore"`
	// StatefulTypes adds resource types (or overrides built-ins).
	StatefulTypes map[string]triage.Stateful `yaml:"stateful_types"`
	// SensitivePorts adds ports that are critical when world-open.
	SensitivePorts map[int]string `yaml:"sensitive_ports"`
}

var knownRules = map[string]bool{
	triage.RuleDestroyStateful: true, triage.RuleProtectionRemoved: true,
	triage.RuleIAMWidening: true, triage.RuleNetworkExposure: true,
	triage.RuleUnguardedStateful: true, triage.RuleDrift: true,
	triage.RuleDestroy: true, triage.RuleReplace: true,
}

// Load reads a config file. A missing file at the default path is not an
// error; a missing explicit path is.
func Load(path string, explicit bool) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return &Config{}, nil
		}
		return nil, err
	}
	return Parse(b)
}

// Parse decodes and validates a config document. Unknown keys are errors,
// so a typo cannot silently disable a gate.
func Parse(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("config: %w", err)
	}
	if c.FailOn != "" {
		if _, err := triage.ParseSeverity(c.FailOn); err != nil {
			return nil, fmt.Errorf("config: fail_on: %w", err)
		}
	}
	for i, ap := range c.Approvals {
		if ap.Label == "" {
			return nil, fmt.Errorf("config: approvals[%d]: label is required", i)
		}
		if err := checkRules(ap.Rules); err != nil {
			return nil, fmt.Errorf("config: approvals[%d]: %w", i, err)
		}
		if ap.MinSeverity != "" {
			if _, err := triage.ParseSeverity(ap.MinSeverity); err != nil {
				return nil, fmt.Errorf("config: approvals[%d]: %w", i, err)
			}
		}
	}
	for i, ig := range c.Ignore {
		if ig.Address == "" {
			return nil, fmt.Errorf("config: ignore[%d]: address is required", i)
		}
		if err := checkRules(ig.Rules); err != nil {
			return nil, fmt.Errorf("config: ignore[%d]: %w", i, err)
		}
	}
	for t, s := range c.StatefulTypes {
		if s.Kind == "" {
			return nil, fmt.Errorf("config: stateful_types.%s: kind is required", t)
		}
		if s.Loss == "" {
			s.Loss = "its data"
			c.StatefulTypes[t] = s
		}
	}
	return &c, nil
}

func checkRules(rules []string) error {
	for _, r := range rules {
		if !knownRules[r] {
			return fmt.Errorf("unknown rule %q", r)
		}
	}
	return nil
}

// Options converts the config to analysis options.
func (c *Config) Options() triage.Options {
	return triage.Options{
		ExtraStateful:       c.StatefulTypes,
		ExtraSensitivePorts: c.SensitivePorts,
		Ignore:              c.Ignore,
	}
}
