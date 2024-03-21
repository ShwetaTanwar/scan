package config

import (
	"regexp"
	"strings"
)

type Allowlist struct {
	Description string
	Regexes     []*regexp.Regexp
	RegexTarget string
	Paths       []*regexp.Regexp
	Commits     []string
	StopWords   []string
}

// returns true if the commit is allowed to be ignored.
func (a *Allowlist) CommitAllowed(c string) bool {
	if c == "" {
		return false
	}
	for _, commit := range a.Commits {
		if commit == c {
			return true
		}
	}
	return false
}

// PathAllowed returns true if the path is allowed to be ignored.
func (a *Allowlist) PathAllowed(path string) bool {
	return anyRegexMatch(path, a.Paths)
}

// RegexAllowed returns true if the regex is allowed to be ignored.
func (a *Allowlist) RegexAllowed(s string) bool {
	return anyRegexMatch(s, a.Regexes)
}

func (a *Allowlist) ContainsStopWord(s string) bool {
	s = strings.ToLower(s)
	for _, stopWord := range a.StopWords {
		if strings.Contains(s, strings.ToLower(stopWord)) {
			return true
		}
	}
	return false
}
