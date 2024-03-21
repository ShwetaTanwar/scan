package models

import "strings"

// Finding contains information about strings that
// have been captured by a tree-sitter query.
type Finding struct {
	Description string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
	Line        string `json:"-"`
	Match       string
	Secret      string
	File        string
	SymlinkFile string
	Commit      string
	Entropy     float32
	Author      string
	Email       string
	Date        string
	Message     string
	Tags        []string
	RuleID      string
	Fingerprint string
}

// Redact removes sensitive information from a finding.
func (f *Finding) Redact() {
	f.Line = strings.Replace(f.Line, f.Secret, "REDACTED", -1)
	f.Match = strings.Replace(f.Match, f.Secret, "REDACTED", -1)
	f.Secret = "REDACTED"
}
