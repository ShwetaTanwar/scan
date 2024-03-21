package config

import (
	"regexp"
)

// Rules contain information that define details on how to detect secrets
type Rule struct {
	Description string
	RuleID      string
	Entropy     float64
	SecretGroup int
	Regex       *regexp.Regexp
	Path        *regexp.Regexp
	Tags        []string
	Keywords    []string
	Allowlist   Allowlist
}
