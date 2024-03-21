package git

import (
	"bufio"
	"fmt"
	"initz/config"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/gitleaks/go-gitdiff/gitdiff"
	"github.com/rs/zerolog/log"
)

var Err bool

func GitLog(source string) (<-chan *gitdiff.File, error) {
	sourceClean := filepath.Clean(source)
	cmd := exec.Command("git", "-C", sourceClean, "log", "-p", "-U0", "--full-history", "--all")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	go listenForStdErr(stderr)

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	time.Sleep(50 * time.Millisecond)
	return gitdiff.Parse(stdout)
}
func listenForStdErr(stderr io.ReadCloser) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {

		if strings.Contains(scanner.Text(),
			"exhaustive rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"inexact rename detection was skipped") ||
			strings.Contains(scanner.Text(),
				"you may want to set your diff.renameLimit") {
			log.Warn().Msg(scanner.Text())
		} else {
			currentTime := time.Now()
			fmt.Printf("%s %s %s [git] \n", currentTime.Format("03:04PM"), config.Red("ERR"), scanner.Text())
			Err = true
		}
	}
}
