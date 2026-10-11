package security

import (
	"reflect"
	"testing"
)

func TestObserveCountsFailedSSHConnectionsOnce(t *testing.T) {
	w := NewWatcher()
	w.sources = 1

	for _, line := range []string{
		"Jan  1 11:00:00 web-1 sshd[123]: Invalid user admin from 198.51.100.7 port 4000",
		"Jan  1 11:00:01 web-1 sshd[123]: Failed password for invalid user admin from 198.51.100.7 port 4000 ssh2",
		"Jan  1 11:00:02 web-1 sshd[123]: Failed password for invalid user admin from 198.51.100.7 port 4000 ssh2",
		"2026-01-01T11:00:03+0000 web-1 sshd-session[456]: Failed publickey for root from 198.51.100.8 port 22 ssh2",
		"Jan  1 11:00:04 web-1 sshd[789]: pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=198.51.100.9",
		"Jan  1 11:00:05 web-1 sshd[999]: Accepted publickey for deploy from 203.0.113.1 port 50000 ssh2",
		"Jan  1 11:00:06 web-1 sudo[111]: pam_unix(sudo:auth): authentication failure; logname=deploy",
	} {
		w.Observe(line)
	}

	if counts := w.Take(); counts == nil || counts.FailedLogins != 3 {
		t.Fatalf("got %+v, want 3 failed logins", counts)
	}
	if counts := w.Take(); counts.FailedLogins != 0 {
		t.Fatalf("expected counts to reset, got %+v", counts)
	}
}

func TestObserveCountsOutOfMemoryKills(t *testing.T) {
	w := NewWatcher()
	w.sources = 1

	w.Observe("kernel: Out of memory: Killed process 1234 (mysqld) total-vm:2000kB, anon-rss:1000kB")
	w.Observe("kernel: Memory cgroup out of memory: Killed process 5678 (php-fpm) total-vm:100kB")
	w.Observe("kernel: Out of memory: Killed process 1300 (mysqld) total-vm:2000kB")

	want := &Counts{OOMKills: 3, OOMKilled: []string{"mysqld", "php-fpm"}}
	if counts := w.Take(); !reflect.DeepEqual(counts, want) {
		t.Fatalf("got %+v, want %+v", counts, want)
	}
}

func TestTakeIsNilWithoutReadableLogs(t *testing.T) {
	if counts := NewWatcher().Take(); counts != nil {
		t.Fatalf("got %+v, want nil", counts)
	}
}

func TestResolve(t *testing.T) {
	exists := func(paths ...string) func(string) bool {
		return func(path string) bool {
			for _, candidate := range paths {
				if candidate == path {
					return true
				}
			}
			return false
		}
	}

	cases := []struct {
		name     string
		kind     string
		exists   func(string) bool
		journal  bool
		wantPath string
		wantArgs []string
	}{
		{"auth file", "auth", exists("/var/log/secure"), true, "/var/log/secure", nil},
		{"auth journal", "auth", exists(), true, "", []string{"SYSLOG_FACILITY=4", "SYSLOG_FACILITY=10"}},
		{"kernel journal", "kernel", exists("/var/log/kern.log"), true, "", []string{"--dmesg"}},
		{"kernel file", "kernel", exists("/var/log/kern.log"), false, "/var/log/kern.log", nil},
		{"nothing", "auth", exists(), false, "", nil},
	}

	for _, tc := range cases {
		path, args := Resolve(tc.kind, tc.exists, tc.journal)
		if path != tc.wantPath || !reflect.DeepEqual(args, tc.wantArgs) {
			t.Errorf("%s: got %q %v, want %q %v", tc.name, path, args, tc.wantPath, tc.wantArgs)
		}
	}
}
