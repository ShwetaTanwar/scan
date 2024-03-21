package cmd

import (
	"context"
	"fmt"
	"initz/config"
	"initz/git"
	"initz/models"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/semgroup"
	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/h2non/filetype"
	ahocorasick "github.com/petar-dambovaliev/aho-corasick"
	"github.com/rs/zerolog/log"
)

type GitScanType int

const (
	DetectType GitScanType = iota
	ProtectType
	ProtectStagedType
	gitleaksAllowSignature = "regex:ignore"
)

// Detector is the main detector struct
type Detector struct {
	Config         config.Config
	Redact         bool
	Verbose        bool
	commitMap      map[string]bool
	findingMutex   *sync.Mutex
	findings       []models.Finding
	prefilter      ahocorasick.AhoCorasick
	baseline       []models.Finding
	baselinePath   string
	gitleaksIgnore map[string]bool
}
type Fragment struct {
	Raw            string
	FilePath       string
	SymlinkFile    string
	CommitSHA      string
	newlineIndices [][]int
	keywords       map[string]bool
}

// NewDetector creates a new detector with the given config
func NewDetector(cfg config.Config) *Detector {
	builder := ahocorasick.NewAhoCorasickBuilder(ahocorasick.Opts{
		AsciiCaseInsensitive: true,
		MatchOnlyWholeWords:  false,
		MatchKind:            ahocorasick.LeftMostLongestMatch,
		DFA:                  true,
	})

	return &Detector{
		commitMap:      make(map[string]bool),
		gitleaksIgnore: make(map[string]bool),
		findingMutex:   &sync.Mutex{},
		findings:       make([]models.Finding, 0),
		Config:         cfg,
		prefilter:      builder.Build(cfg.Keywords),
	}
}

// DetectBytes scans the given bytes and returns a list of findings
func (d *Detector) DetectBytes(content []byte) []models.Finding {
	return d.DetectString(string(content))
}

// DetectString scans the given string and returns a list of findings
func (d *Detector) DetectString(content string) []models.Finding {
	return d.Detect(Fragment{
		Raw: content,
	})
}

// detectRule scans the given fragment for the given rule and returns a list of findings
func (d *Detector) detectRule(fragment Fragment, rule config.Rule) []models.Finding {
	var findings []models.Finding

	// check if filepath or commit is allowed for this rule
	if rule.Allowlist.CommitAllowed(fragment.CommitSHA) ||
		rule.Allowlist.PathAllowed(fragment.FilePath) {
		return findings
	}

	if rule.Path != nil && rule.Regex == nil {
		// Path _only_ rule
		if rule.Path.Match([]byte(fragment.FilePath)) {
			finding := models.Finding{
				Description: rule.Description,
				File:        fragment.FilePath,
				SymlinkFile: fragment.SymlinkFile,
				RuleID:      rule.RuleID,
				Match:       fmt.Sprintf("file detected: %s", fragment.FilePath),
				Tags:        rule.Tags,
			}
			return append(findings, finding)
		}
	} else if rule.Path != nil {
		if !rule.Path.Match([]byte(fragment.FilePath)) {
			return findings
		}
	}

	// if path only rule, skip content checks
	if rule.Regex == nil {
		return findings
	}
	matchIndices := rule.Regex.FindAllStringIndex(fragment.Raw, -1)
	for _, matchIndex := range matchIndices {
		// extract secret from match
		secret := strings.Trim(fragment.Raw[matchIndex[0]:matchIndex[1]], "\n")
		loc := location(fragment, matchIndex)
		if matchIndex[1] > loc.endLineIndex {
			loc.endLineIndex = matchIndex[1]
		}
		finding := models.Finding{
			Description: rule.Description,
			File:        fragment.FilePath,
			SymlinkFile: fragment.SymlinkFile,
			RuleID:      rule.RuleID,
			StartLine:   loc.startLine,
			EndLine:     loc.endLine,
			StartColumn: loc.startColumn,
			EndColumn:   loc.endColumn,
			Secret:      secret,
			Match:       secret,
			Tags:        rule.Tags,
			Line:        fragment.Raw[loc.startLineIndex:loc.endLineIndex],
		}
		if strings.Contains(fragment.Raw[loc.startLineIndex:loc.endLineIndex],
			gitleaksAllowSignature) {
			continue
		}
		// extract secret from secret group if set
		if rule.SecretGroup != 0 {
			groups := rule.Regex.FindStringSubmatch(secret)
			if len(groups) <= rule.SecretGroup || len(groups) == 0 {
				// Config validation should prevent this
				continue
			}
			secret = groups[rule.SecretGroup]
			finding.Secret = secret
		}

		// check if the regexTarget is defined in the allowlist "regexes" entry
		allowlistTarget := finding.Secret
		switch rule.Allowlist.RegexTarget {
		case "match":
			allowlistTarget = finding.Match
		case "line":
			allowlistTarget = finding.Line
		}
		globalAllowlistTarget := finding.Secret
		switch d.Config.Allowlist.RegexTarget {
		case "match":
			globalAllowlistTarget = finding.Match
		case "line":
			globalAllowlistTarget = finding.Line
		}
		if rule.Allowlist.RegexAllowed(allowlistTarget) ||
			d.Config.Allowlist.RegexAllowed(globalAllowlistTarget) {
			continue
		}
		// check if the secret is in the list of stopwords
		if rule.Allowlist.ContainsStopWord(finding.Secret) ||
			d.Config.Allowlist.ContainsStopWord(finding.Secret) {
			continue
		}
		// check entropy
		entropy := shannonEntropy(finding.Secret)
		finding.Entropy = float32(entropy)
		if rule.Entropy != 0.0 {
			if entropy <= rule.Entropy {
				// entropy is too low, skip this finding
				continue
			}
			if strings.HasPrefix(rule.RuleID, "generic") {
				if !containsDigit(secret) {
					continue
				}
			}
		}
		findings = append(findings, finding)
	}
	return findings
}

func (d *Detector) DetectGit(source string) ([]models.Finding, error) {
	var (
		gitdiffFiles <-chan *gitdiff.File
		err          error
	)
	gitdiffFiles, err = git.GitLog(source)
	if err != nil {
		return d.findings, err
	}
	s := semgroup.NewGroup(context.Background(), 4)
	for gitdiffFile := range gitdiffFiles {
		gitdiffFile := gitdiffFile
		if gitdiffFile.IsBinary || gitdiffFile.IsDelete {
			continue
		}

		// Check if commit is allowed
		commitSHA := ""
		if gitdiffFile.PatchHeader != nil {
			commitSHA = gitdiffFile.PatchHeader.SHA
			if d.Config.Allowlist.CommitAllowed(gitdiffFile.PatchHeader.SHA) {
				continue
			}
		}
		d.addCommit(commitSHA)
		s.Go(func() error {
			for _, textFragment := range gitdiffFile.TextFragments {
				if textFragment == nil {
					return nil
				}
				fragment := Fragment{
					Raw:       textFragment.Raw(gitdiff.OpAdd),
					CommitSHA: commitSHA,
					FilePath:  gitdiffFile.NewName,
				}
				for _, finding := range d.Detect(fragment) {
					d.addFinding(augmentGitFinding(finding, textFragment, gitdiffFile))
				}
			}
			return nil
		})
	}

	if err := s.Wait(); err != nil {
		//fmt.Println("s.wait()err", err)
		return d.findings, err
	}

	currentTime := time.Now()
	if len(d.commitMap) != 0 {
		fmt.Printf("%s %s %d commits scanned. \n", currentTime.Format("03:04PM"), config.Green("INF"), len(d.commitMap))
	}
	return d.findings, nil
}

// Detect scans the given fragment and returns a list of findings
func (d *Detector) Detect(fragment Fragment) []models.Finding {
	var findings []models.Finding

	// initiate fragment keywords
	fragment.keywords = make(map[string]bool)

	// check if filepath is allowed
	if fragment.FilePath != "" && (d.Config.Allowlist.PathAllowed(fragment.FilePath) ||
		fragment.FilePath == d.Config.Path || (d.baselinePath != "" && fragment.FilePath == d.baselinePath)) {
		//fmt.Println("check if filepath allowed", findings)
		return findings
	}

	// add newline indices for location calculation in detectRule
	fragment.newlineIndices = regexp.MustCompile("\n").FindAllStringIndex(fragment.Raw, -1)

	// build keyword map for prefiltering rules
	normalizedRaw := strings.ToLower(fragment.Raw)
	matches := d.prefilter.FindAll(normalizedRaw)
	for _, m := range matches {
		fragment.keywords[normalizedRaw[m.Start():m.End()]] = true
	}

	for _, rule := range d.Config.Rules {
		if len(rule.Keywords) == 0 {
			// if not keywords are associated with the rule always scan the
			// fragment using the rule
			findings = append(findings, d.detectRule(fragment, rule)...)
			continue
		}
		fragmentContainsKeyword := false
		// check if keywords are in the fragment
		for _, k := range rule.Keywords {
			if _, ok := fragment.keywords[strings.ToLower(k)]; ok {
				fragmentContainsKeyword = true
			}
		}
		if fragmentContainsKeyword {
			findings = append(findings, d.detectRule(fragment, rule)...)
		}
	}
	return filter(findings, d.Redact)
}

// addFinding synchronously adds a finding to the findings slice
func (d *Detector) addFinding(finding models.Finding) {
	if finding.Commit == "" {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%d", finding.File, finding.RuleID, finding.StartLine)
	} else {
		finding.Fingerprint = fmt.Sprintf("%s:%s:%s:%d", finding.Commit, finding.File, finding.RuleID, finding.StartLine)
	}
	// check if we should ignore this finding
	if _, ok := d.gitleaksIgnore[finding.Fingerprint]; ok {
		log.Debug().Msgf("ignoring finding with Fingerprint %s",
			finding.Fingerprint)
		return
	}

	if d.baseline != nil && !IsNew(finding, d.baseline) {
		log.Debug().Msgf("baseline duplicate -- ignoring finding with Fingerprint %s", finding.Fingerprint)
		return
	}

	d.findingMutex.Lock()
	d.findings = append(d.findings, finding)
	if d.Verbose {
		printFinding(finding)
	}
	d.findingMutex.Unlock()
}

// addCommit synchronously adds a commit to the commit slice
func (d *Detector) addCommit(commit string) {
	d.commitMap[commit] = true
}
func printFinding(f models.Finding) {
	// trim all whitespace and tabs
	f.Line = strings.TrimSpace(f.Line)
	f.Secret = strings.TrimSpace(f.Secret)
	f.Match = strings.TrimSpace(f.Match)

	isFileMatch := strings.HasPrefix(f.Match, "file detected:")
	finding := ""
	var secret lipgloss.Style

	// Matches from filenames do not have a |line| or |secret|
	if !isFileMatch {
		matchInLineIDX := strings.Index(f.Line, f.Match)
		secretInMatchIdx := strings.Index(f.Match, f.Secret)

		if matchInLineIDX == -1 {

			matchInLineIDX = 0
		}

		start := f.Line[0:matchInLineIDX]
		startMatchIdx := 0
		if matchInLineIDX > 20 {
			startMatchIdx = matchInLineIDX - 20
			start = "..." + f.Line[startMatchIdx:matchInLineIDX]
		}
		matchBeginning := lipgloss.NewStyle().SetString(f.Match[0:secretInMatchIdx]).Foreground(lipgloss.Color("#f5d445"))
		secret = lipgloss.NewStyle().SetString(f.Secret).
			Bold(true).
			Italic(true).
			Foreground(lipgloss.Color("#f05c07"))
		matchEnd := lipgloss.NewStyle().SetString(f.Match[secretInMatchIdx+len(f.Secret):]).Foreground(lipgloss.Color("#f5d445"))

		lineEndIdx := matchInLineIDX + len(f.Match)
		if len(f.Line)-1 <= lineEndIdx {
			lineEndIdx = len(f.Line) - 1
		}

		lineEnd := f.Line[lineEndIdx:]

		if len(f.Secret) > 100 {
			secret = lipgloss.NewStyle().SetString(f.Secret[0:100] + "...").
				Bold(true).
				Italic(true).
				Foreground(lipgloss.Color("#f05c07"))
		}
		if len(lineEnd) > 20 {
			lineEnd = lineEnd[0:20] + "..."
		}

		finding = fmt.Sprintf("%s%s%s%s%s\n", strings.TrimPrefix(strings.TrimLeft(start, " "), "\n"), matchBeginning, secret, matchEnd, lineEnd)
	}

	if isFileMatch {
		fmt.Printf("%-12s %s\n", "Finding:", f.Match)
		fmt.Printf("%-12s %s\n", "Secret:", f.Secret)
	} else {
		fmt.Printf("%-12s %s", "Finding:", finding)
		fmt.Printf("%-12s %s\n", "Secret:", secret)
	}

	fmt.Printf("%-12s %s\n", "RuleID:", f.RuleID)
	fmt.Printf("%-12s %f\n", "Entropy:", f.Entropy)
	if f.File == "" {
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "File:", f.File)
	fmt.Printf("%-12s %d\n", "Line:", f.StartLine)
	if f.Commit == "" {
		fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
		fmt.Println("")
		return
	}
	fmt.Printf("%-12s %s\n", "Commit:", f.Commit)
	fmt.Printf("%-12s %s\n", "Author:", f.Author)
	fmt.Printf("%-12s %s\n", "Email:", f.Email)
	fmt.Printf("%-12s %s\n", "Date:", f.Date)
	fmt.Printf("%-12s %s\n", "Fingerprint:", f.Fingerprint)
	fmt.Println("")
}

func shannonEntropy(data string) (entropy float64) {
	if data == "" {
		return 0
	}

	charCounts := make(map[rune]int)
	for _, char := range data {
		charCounts[char]++
	}

	invLength := 1.0 / float64(len(data))
	for _, count := range charCounts {
		freq := float64(count) * invLength
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// filter will dedupe and redact findings
func filter(findings []models.Finding, redact bool) []models.Finding {
	var retFindings []models.Finding
	for _, f := range findings {
		include := true
		if strings.Contains(strings.ToLower(f.RuleID), "generic") {
			for _, fPrime := range findings {
				if f.StartLine == fPrime.StartLine &&
					f.Commit == fPrime.Commit &&
					f.RuleID != fPrime.RuleID &&
					strings.Contains(fPrime.Secret, f.Secret) &&
					!strings.Contains(strings.ToLower(fPrime.RuleID), "generic") {

					genericMatch := strings.Replace(f.Match, f.Secret, "REDACTED", -1)
					betterMatch := strings.Replace(fPrime.Match, fPrime.Secret, "REDACTED", -1)
					log.Trace().Msgf("skipping %s finding (%s), %s rule takes precendence (%s)", f.RuleID, genericMatch, fPrime.RuleID, betterMatch)
					include = false
					break
				}
			}
		}

		if redact {
			f.Redact()
		}
		if include {
			retFindings = append(retFindings, f)
		}
	}
	return retFindings
}

func augmentGitFinding(finding models.Finding, textFragment *gitdiff.TextFragment, f *gitdiff.File) models.Finding {
	if !strings.HasPrefix(finding.Match, "file detected") {
		finding.StartLine += int(textFragment.NewPosition)
		finding.EndLine += int(textFragment.NewPosition)
	}

	if f.PatchHeader != nil {
		finding.Commit = f.PatchHeader.SHA
		finding.Message = f.PatchHeader.Message()
		if f.PatchHeader.Author != nil {
			finding.Author = f.PatchHeader.Author.Name
			finding.Email = f.PatchHeader.Author.Email
		}
		finding.Date = f.PatchHeader.AuthorDate.UTC().Format(time.RFC3339)
	}
	return finding
}
func containsDigit(s string) bool {
	for _, c := range s {
		switch c {
		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			return true
		}

	}
	return false
}
func IsNew(finding models.Finding, baseline []models.Finding) bool {
	// Explicitly testing each property as it gives significantly better performance in comparison to cmp.Equal(). Drawback is that
	// the code requires maintanance if/when the Finding struct changes
	for _, b := range baseline {

		if finding.Author == b.Author &&
			finding.Commit == b.Commit &&
			finding.Date == b.Date &&
			finding.Description == b.Description &&
			finding.Email == b.Email &&
			finding.EndColumn == b.EndColumn &&
			finding.EndLine == b.EndLine &&
			finding.Entropy == b.Entropy &&
			finding.File == b.File &&
			finding.Match == b.Match &&
			finding.Message == b.Message &&
			finding.RuleID == b.RuleID &&
			finding.Secret == b.Secret &&
			finding.StartColumn == b.StartColumn &&
			finding.StartLine == b.StartLine {
			return false
		}
	}
	return true
}

type Location struct {
	startLine      int
	endLine        int
	startColumn    int
	endColumn      int
	startLineIndex int
	endLineIndex   int
}

func location(fragment Fragment, matchIndex []int) Location {
	var (
		prevNewLine int
		location    Location
		lineSet     bool
		_lineNum    int
	)

	start := matchIndex[0]
	end := matchIndex[1]
	location.startLineIndex = 0
	if len(fragment.newlineIndices) == 0 {
		fragment.newlineIndices = [][]int{
			{len(fragment.Raw), len(fragment.Raw) + 1},
		}
	}

	for lineNum, pair := range fragment.newlineIndices {
		_lineNum = lineNum
		newLineByteIndex := pair[0]
		if prevNewLine <= start && start < newLineByteIndex {
			lineSet = true
			location.startLine = lineNum
			location.endLine = lineNum
			location.startColumn = (start - prevNewLine) + 1 // +1 because counting starts at 1
			location.startLineIndex = prevNewLine
			location.endLineIndex = newLineByteIndex
		}
		if prevNewLine < end && end <= newLineByteIndex {
			location.endLine = lineNum
			location.endColumn = (end - prevNewLine)
			location.endLineIndex = newLineByteIndex
		}
		prevNewLine = pair[0]
	}

	if !lineSet {

		location.startColumn = (start - prevNewLine) + 1 // +1 because counting starts at 1
		location.endColumn = (end - prevNewLine)
		location.startLine = _lineNum + 1
		location.endLine = _lineNum + 1
		i := 0
		for end+i < len(fragment.Raw) {
			if fragment.Raw[end+i] == '\n' {
				break
			}
			if fragment.Raw[end+i] == '\r' {
				break
			}
			i++
		}
		location.endLineIndex = end + i
	}
	return location
}
func (d *Detector) DetectFiles(source string) ([]models.Finding, error) {
	s := semgroup.NewGroup(context.Background(), 4)
	paths := make(chan scanTarget)
	s.Go(func() error {
		defer close(paths)
		return filepath.Walk(source,
			func(path string, fInfo os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if fInfo.Name() == ".git" && fInfo.IsDir() {
					return filepath.SkipDir
				}
				if fInfo.Size() == 0 {
					return nil
				}
				if fInfo.Mode().IsRegular() {
					paths <- scanTarget{
						Path:    path,
						Symlink: "",
					}
				}
				return nil
			})
	})
	for pa := range paths {
		p := pa
		s.Go(func() error {
			b, err := os.ReadFile(p.Path)
			if err != nil {
				return err
			}

			mimetype, err := filetype.Match(b)
			if err != nil {
				return err
			}
			if mimetype.MIME.Type == "application" {
				return nil // skip binary files
			}

			fragment := Fragment{
				Raw:      string(b),
				FilePath: p.Path,
			}
			if p.Symlink != "" {
				fragment.SymlinkFile = p.Symlink
			}
			for _, finding := range d.Detect(fragment) {
				// need to add 1 since line counting starts at 1
				finding.EndLine++
				finding.StartLine++
				d.addFinding(finding)
			}

			return nil
		})
	}

	if err := s.Wait(); err != nil {
		return d.findings, err
	}

	return d.findings, nil
}

type scanTarget struct {
	Path    string
	Symlink string
}
