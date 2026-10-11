// Package update replaces the agent binary with the version the dashboard reports as latest.
package update

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// DefaultDownloadURL is used when the configuration file doesn't name one.
const DefaultDownloadURL = "https://github.com/lifelessrasel/alertly-agent/releases/latest/download"

const maxBinarySize = 64 << 20

// Asset is the release file name for this platform.
func Asset() (string, error) {
	switch runtime.GOARCH {
	case "amd64", "arm64":
		return "alertly-agent-linux-" + runtime.GOARCH, nil
	case "arm":
		return "alertly-agent-linux-armv7", nil
	}

	return "", fmt.Errorf("unsupported architecture %s", runtime.GOARCH)
}

// ReleaseURL is where a version's files are published. GitHub serves the newest release under
// /latest/download, so a specific version needs its own tag path.
func ReleaseURL(base, version string) string {
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, "/releases/latest/download") {
		return strings.TrimSuffix(base, "/latest/download") + "/download/v" + strings.TrimPrefix(version, "v")
	}

	return base
}

// SameVersion compares versions with or without a leading "v".
func SameVersion(a, b string) bool {
	return strings.TrimPrefix(strings.TrimSpace(a), "v") == strings.TrimPrefix(strings.TrimSpace(b), "v")
}

// Install downloads version, verifies its checksum and that it runs, and atomically replaces binPath.
func Install(ctx context.Context, downloadURL, version, binPath string) error {
	if !strings.HasPrefix(downloadURL, "https://") {
		return fmt.Errorf("refusing to download over a non-HTTPS URL: %s", downloadURL)
	}
	asset, err := Asset()
	if err != nil {
		return err
	}
	base := ReleaseURL(downloadURL, version)
	client := &http.Client{Timeout: 5 * time.Minute}

	sums, err := fetch(ctx, client, base+"/"+asset+".sha256", 4096)
	if err != nil {
		return err
	}
	want, err := ParseChecksum(string(sums), asset)
	if err != nil {
		return err
	}

	binary, err := fetch(ctx, client, base+"/"+asset, maxBinarySize)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(binary)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("checksum mismatch for %s: got %s, want %s", asset, got, want)
	}

	staged := filepath.Join(filepath.Dir(binPath), "."+filepath.Base(binPath)+".new")
	if err := os.WriteFile(staged, binary, 0o755); err != nil {
		return err
	}
	defer os.Remove(staged)

	output, err := exec.CommandContext(ctx, staged, "--version").Output()
	if err != nil {
		return fmt.Errorf("the new binary doesn't run: %w", err)
	}
	if !SameVersion(string(output), version) {
		return fmt.Errorf("the new binary reports version %q, want %q", strings.TrimSpace(string(output)), version)
	}

	return os.Rename(staged, binPath)
}

// ParseChecksum reads a sha256sum line ("<hash>  <file>") for asset.
func ParseChecksum(content, asset string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if len(fields) > 1 && strings.TrimPrefix(fields[1], "*") != asset {
			continue
		}
		if len(fields[0]) == 64 {
			if _, err := hex.DecodeString(fields[0]); err == nil {
				return strings.ToLower(fields[0]), nil
			}
		}
	}

	return "", fmt.Errorf("no checksum for %s", asset)
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, limit)
	}

	return body, nil
}
