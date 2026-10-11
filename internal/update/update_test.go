package update

import (
	"context"
	"strings"
	"testing"
)

func TestReleaseURLPinsTheVersionOnGitHub(t *testing.T) {
	cases := map[[2]string]string{
		{DefaultDownloadURL, "0.2.0"}:                    "https://github.com/lifelessrasel/alertly-agent/releases/download/v0.2.0",
		{DefaultDownloadURL + "/", "v0.2.0"}:             "https://github.com/lifelessrasel/alertly-agent/releases/download/v0.2.0",
		{"https://downloads.example.com/agent", "0.2.0"}: "https://downloads.example.com/agent",
	}

	for input, want := range cases {
		if got := ReleaseURL(input[0], input[1]); got != want {
			t.Errorf("ReleaseURL(%q, %q) = %q, want %q", input[0], input[1], got, want)
		}
	}
}

func TestParseChecksum(t *testing.T) {
	hash := strings.Repeat("ab", 32)

	if got, err := ParseChecksum(hash+"  alertly-agent-linux-amd64\n", "alertly-agent-linux-amd64"); err != nil || got != hash {
		t.Fatalf("got %q %v, want %q", got, err, hash)
	}
	if got, err := ParseChecksum(strings.ToUpper(hash)+"\n", "alertly-agent-linux-amd64"); err != nil || got != hash {
		t.Fatalf("bare hash: got %q %v, want %q", got, err, hash)
	}
	if _, err := ParseChecksum(hash+"  alertly-agent-linux-arm64\n", "alertly-agent-linux-amd64"); err == nil {
		t.Fatal("expected an error for another file's checksum")
	}
	if _, err := ParseChecksum("not-a-hash  alertly-agent-linux-amd64\n", "alertly-agent-linux-amd64"); err == nil {
		t.Fatal("expected an error for a malformed checksum")
	}
}

func TestInstallRefusesPlainHTTP(t *testing.T) {
	if err := Install(context.Background(), "http://example.com/agent", "0.2.0", t.TempDir()+"/alertly-agent"); err == nil {
		t.Fatal("expected plain HTTP to be refused")
	}
}

func TestSameVersion(t *testing.T) {
	if !SameVersion("v0.2.0\n", "0.2.0") || SameVersion("0.1.1", "0.2.0") {
		t.Fatal("unexpected version comparison")
	}
}
