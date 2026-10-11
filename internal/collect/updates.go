package collect

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Updates says whether the server needs a restart and how many package updates are waiting.
// Counts are nil when the package manager isn't supported or couldn't be asked.
type Updates struct {
	RebootRequired bool `json:"reboot_required"`
	Pending        *int `json:"pending,omitempty"`
	Security       *int `json:"security,omitempty"`
}

// Asking the package manager takes a few seconds, so it only happens every few hours.
const (
	updatesInterval = 6 * time.Hour
	updatesTimeout  = 60 * time.Second
)

// UpdateChecker remembers the last package count between samples. Every check is read-only: apt only
// simulates the upgrade and dnf only reads its cache, so nothing is installed or downloaded.
type UpdateChecker struct {
	checkedAt     time.Time
	pending       *int
	security      *int
	rebootFromDnf bool
}

// NewUpdateChecker creates a checker that asks the package manager on the first sample.
func NewUpdateChecker() *UpdateChecker {
	return &UpdateChecker{}
}

// Collect returns the current state, asking the package manager again when the last answer is old.
func (u *UpdateChecker) Collect(ctx context.Context) *Updates {
	if time.Since(u.checkedAt) >= updatesInterval {
		u.checkedAt = time.Now()
		u.pending, u.security, u.rebootFromDnf = countUpdates(ctx)
	}

	return &Updates{
		RebootRequired: u.rebootFromDnf || fileExists("/run/reboot-required") || fileExists("/var/run/reboot-required"),
		Pending:        u.pending,
		Security:       u.security,
	}
}

func countUpdates(ctx context.Context) (pending, security *int, rebootRequired bool) {
	if _, err := exec.LookPath("apt-get"); err == nil {
		output, code, err := runFor(ctx, updatesTimeout, "apt-get", "-s", "-o", "Debug::NoLocking=1", "upgrade")
		if err != nil || code != 0 {
			return nil, nil, false
		}
		all, sec := parseAptSimulation(output)

		return &all, &sec, false
	}

	if _, err := exec.LookPath("dnf"); err == nil {
		output, code, _ := runFor(ctx, updatesTimeout, "dnf", "-q", "--cacheonly", "check-update")
		if code != 0 && code != 100 {
			return nil, nil, false
		}
		all := parseDnfCheckUpdate(output)
		pending = &all

		if advisories, code, err := runFor(ctx, updatesTimeout, "dnf", "-q", "--cacheonly", "updateinfo", "list", "--security"); err == nil && code == 0 {
			sec := parseDnfSecurityList(advisories)
			security = &sec
		}

		if _, err := exec.LookPath("needs-restarting"); err == nil {
			_, code, _ := runFor(ctx, updatesTimeout, "needs-restarting", "-r")
			rebootRequired = code == 1
		}

		return pending, security, rebootRequired
	}

	return nil, nil, false
}

// parseAptSimulation counts the packages "apt-get -s upgrade" would install, and how many come from a security pocket.
func parseAptSimulation(output string) (pending, security int) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "Inst ") {
			continue
		}
		pending++
		if strings.Contains(line, "-security") {
			security++
		}
	}

	return pending, security
}

// parseDnfCheckUpdate counts the "name.arch version repo" lines, stopping at the obsoletes section.
func parseDnfCheckUpdate(output string) int {
	count := 0
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Obsoleting") {
			break
		}
		if fields := strings.Fields(line); len(fields) == 3 && strings.Contains(fields[0], ".") {
			count++
		}
	}

	return count
}

// parseDnfSecurityList counts the distinct packages in "dnf updateinfo list --security".
func parseDnfSecurityList(output string) int {
	packages := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if fields := strings.Fields(scanner.Text()); len(fields) == 3 {
			packages[fields[2]] = true
		}
	}

	return len(packages)
}

// runFor runs a command with its own timeout and returns the exit code, since package managers use
// non-zero codes to mean "updates available".
func runFor(ctx context.Context, timeout time.Duration, name string, args ...string) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).Output()

	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(output), exitErr.ExitCode(), nil
	}

	return string(output), 0, err
}

func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}
