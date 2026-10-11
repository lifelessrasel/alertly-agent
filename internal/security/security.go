// Package security watches the authentication and kernel logs for failed SSH logins, sudo use, new user
// accounts, admin group changes and out-of-memory kills. Lines are only counted on the server: only counts
// and user, group and process names are reported, never the commands that were run.
package security

import (
	"bufio"
	"context"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Counts is what happened since the previous report.
type Counts struct {
	FailedLogins uint64   `json:"failed_logins"`
	OOMKills     uint64   `json:"oom_kills"`
	OOMKilled    []string `json:"oom_killed,omitempty"`
	SudoCommands uint64   `json:"sudo_commands"`
	SudoUsers    []string `json:"sudo_users,omitempty"`
	NewUsers     []string `json:"new_users,omitempty"`
	AdminGrants  []string `json:"admin_grants,omitempty"`
}

const maxNames = 10

// adminGroups give root or root-equivalent access.
const adminGroups = `sudo|wheel|admin|root|docker`

var (
	sshFailure = regexp.MustCompile(`\bsshd(?:-session)?\[(\d+)\]: .*(?:Failed \S+ for |Invalid user |authentication failure)`)
	oomKill    = regexp.MustCompile(`Killed process \d+ \(([^)]{1,64})\)`)
	sudoUse    = regexp.MustCompile(`\bsudo(?:\[\d+\])?:\s+(\S{1,32}) : (?:TTY|PWD|USER)=.*\bCOMMAND=`)
	newUser    = regexp.MustCompile(`\buseradd\[\d+\]: new user: name=([^,\s]{1,32})`)
	groupAdd   = regexp.MustCompile(`\busermod\[\d+\]: add '([^']{1,32})' to group '(` + adminGroups + `)'`)
	groupGrant = regexp.MustCompile(`\bgpasswd\[\d+\]: user (\S{1,32}) added by \S+ to group (` + adminGroups + `)\b`)
)

// Watcher counts security events from the logs it can read.
type Watcher struct {
	mu        sync.Mutex
	sources   int
	failedSSH map[string]bool
	counts    Counts
}

// NewWatcher creates an idle watcher. Call Run to start reading.
func NewWatcher() *Watcher {
	return &Watcher{failedSSH: map[string]bool{}}
}

// Run follows the authentication and kernel logs until ctx is done.
func (w *Watcher) Run(ctx context.Context) {
	journal := hasJournal()
	var wg sync.WaitGroup
	for _, kind := range []string{"auth", "kernel"} {
		path, args := Resolve(kind, fileExists, journal)
		if path == "" && args == nil {
			log.Printf("security: no %s log to read", kind)
			continue
		}
		w.mu.Lock()
		w.sources++
		w.mu.Unlock()

		wg.Add(1)
		go func() {
			defer wg.Done()
			w.follow(ctx, kind, path, args)
		}()
	}
	wg.Wait()
}

// Take returns the counts since the previous call, or nil when no log can be read.
func (w *Watcher) Take() *Counts {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.sources == 0 {
		return nil
	}
	counts := w.counts
	counts.FailedLogins = uint64(len(w.failedSSH))
	w.counts = Counts{}
	w.failedSSH = map[string]bool{}

	return &counts
}

// Observe classifies one log line. Failed SSH logins are counted once per connection (sshd process),
// so several password guesses in one connection count as one failed login.
func (w *Watcher) Observe(line string) {
	if match := sshFailure.FindStringSubmatch(line); match != nil {
		w.mu.Lock()
		w.failedSSH[match[1]] = true
		w.mu.Unlock()
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if match := oomKill.FindStringSubmatch(line); match != nil {
		w.counts.OOMKills++
		w.counts.OOMKilled = appendName(w.counts.OOMKilled, match[1])
		return
	}
	if match := sudoUse.FindStringSubmatch(line); match != nil {
		w.counts.SudoCommands++
		w.counts.SudoUsers = appendName(w.counts.SudoUsers, match[1])
		return
	}
	if match := newUser.FindStringSubmatch(line); match != nil {
		w.counts.NewUsers = appendName(w.counts.NewUsers, match[1])
		return
	}
	if match := groupAdd.FindStringSubmatch(line); match != nil {
		w.counts.AdminGrants = appendName(w.counts.AdminGrants, match[1]+":"+match[2])
		return
	}
	if match := groupGrant.FindStringSubmatch(line); match != nil {
		w.counts.AdminGrants = appendName(w.counts.AdminGrants, match[1]+":"+match[2])
	}
}

func appendName(names []string, name string) []string {
	if len(names) >= maxNames || contains(names, name) {
		return names
	}

	return append(names, name)
}

func (w *Watcher) follow(ctx context.Context, kind, path string, args []string) {
	for ctx.Err() == nil {
		var err error
		if path != "" {
			err = w.tailFile(ctx, path)
		} else {
			err = w.tailJournal(ctx, args)
		}
		if err != nil && ctx.Err() == nil {
			log.Printf("security: %s log: %v", kind, err)
		}

		select {
		case <-ctx.Done():
		case <-time.After(15 * time.Second):
		}
	}
}

// Resolve picks the file or journalctl arguments to read for the "auth" or "kernel" log.
func Resolve(kind string, exists func(string) bool, journal bool) (string, []string) {
	firstFile := func(paths ...string) string {
		for _, path := range paths {
			if exists(path) {
				return path
			}
		}
		return ""
	}

	switch kind {
	case "auth":
		if path := firstFile("/var/log/auth.log", "/var/log/secure"); path != "" {
			return path, nil
		}
		if journal {
			return "", []string{"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"}
		}
	case "kernel":
		if journal {
			return "", []string{"--dmesg"}
		}
		return firstFile("/var/log/kern.log"), nil
	}

	return "", nil
}

const maxLineLength = 8192

// tailFile follows a file from its end, reopening it when it is rotated or truncated.
func (w *Watcher) tailFile(ctx context.Context, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { file.Close() }()

	offset, err := file.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil {
		return err
	}

	reader := bufio.NewReaderSize(file, 64*1024)
	var partial strings.Builder
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		for {
			chunk, err := reader.ReadString('\n')
			offset += int64(len(chunk))
			if partial.Len() < maxLineLength {
				partial.WriteString(chunk)
			}
			if err != nil {
				break
			}
			w.Observe(partial.String())
			partial.Reset()
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		current, err := os.Stat(path)
		if err != nil {
			continue
		}
		if !os.SameFile(info, current) || current.Size() < offset {
			reopened, err := os.Open(path)
			if err != nil {
				continue
			}
			file.Close()
			file, info, offset = reopened, current, 0
			reader.Reset(file)
			partial.Reset()
		}
	}
}

// tailJournal follows journalctl output until it exits.
func (w *Watcher) tailJournal(ctx context.Context, args []string) error {
	cmd := exec.CommandContext(ctx, "journalctl", append([]string{"--follow", "--lines=0", "--output=short-iso", "--no-pager", "--quiet"}, args...)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		w.Observe(scanner.Text())
	}

	return cmd.Wait()
}

func contains(values []string, value string) bool {
	for _, existing := range values {
		if existing == value {
			return true
		}
	}

	return false
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func hasJournal() bool {
	_, err := exec.LookPath("journalctl")
	return err == nil
}
