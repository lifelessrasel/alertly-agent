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

func TestObserveReportsSudoUseNewUsersAndAdminGrants(t *testing.T) {
	w := NewWatcher()
	w.sources = 1

	for _, line := range []string{
		"Jan  1 11:00:00 web-1 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
		"2026-01-01T11:00:01+0000 web-1 sudo[222]:   deploy : PWD=/srv ; USER=root ; COMMAND=/usr/bin/apt update",
		"Jan  1 11:00:02 web-1 sudo:    alice : TTY=pts/1 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
		"Jan  1 11:00:03 web-1 sudo:    mallory : 3 incorrect password attempts ; TTY=pts/2 ; PWD=/tmp ; USER=root ; COMMAND=/bin/sh",
		"Jan  1 11:00:04 web-1 useradd[333]: new user: name=backup, UID=1002, GID=1002, home=/home/backup, shell=/bin/bash",
		"Jan  1 11:00:05 web-1 usermod[334]: add 'backup' to group 'sudo'",
		"Jan  1 11:00:06 web-1 usermod[335]: add 'backup' to group 'www-data'",
		"Jan  1 11:00:07 web-1 gpasswd[336]: user ci added by root to group docker",
	} {
		w.Observe(line)
	}

	want := &Counts{
		SudoCommands: 3,
		SudoUsers:    []string{"deploy", "alice"},
		NewUsers:     []string{"backup"},
		AdminGrants:  []string{"backup:sudo", "ci:docker"},
	}
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

func TestObserveReportsSystemErrors(t *testing.T) {
	w := NewWatcher()
	w.sources = 1

	for _, line := range []string{
		"2026-01-01T11:00:00+0000 web-1 kernel: blk_update_request: I/O error, dev sda, sector 123456 op 0x0:(READ) flags 0x0",
		"2026-01-01T11:00:01+0000 web-1 kernel: I/O error, dev nvme0n1, sector 8 op 0x1:(WRITE) flags 0x800 phys_seg 1 prio class 2",
		"2026-01-01T11:00:02+0000 web-1 kernel: Buffer I/O error on dev sda1, logical block 0, async page read",
		"2026-01-01T11:00:03+0000 web-1 kernel: blk_update_request: I/O error, dev sr0, sector 0 op 0x0:(READ)",
		"2026-01-01T11:00:04+0000 web-1 kernel: EXT4-fs (sda1): Remounting filesystem read-only",
		"2026-01-01T11:00:05+0000 web-1 kernel: XFS (vdb): Corruption of in-memory data detected.  Shutting down filesystem",
		"2026-01-01T11:00:06+0000 web-1 kernel: php-fpm8.3[4321]: segfault at 0 ip 00007f0000000000 sp 00007ffd00000000 error 4 in libc.so.6",
		"2026-01-01T11:00:07+0000 web-1 kernel: traps: node[999] general protection fault ip:55d0 sp:7ffd error:0 in node[55d0+1000]",
		"2026-01-01T11:00:08+0000 web-1 kernel: mce: [Hardware Error]: Machine check events logged",
		"2026-01-01T11:00:09+0000 web-1 kernel: INFO: task mysqld:1234 blocked for more than 120 seconds.",
	} {
		w.Observe(line)
	}

	want := &Counts{
		DiskErrors:          3,
		DiskErrorDevices:    []string{"sda", "nvme0n1", "sda1"},
		ReadOnlyFilesystems: []string{"sda1", "vdb"},
		Crashes:             2,
		Crashed:             []string{"php-fpm8.3", "node"},
		HardwareErrors:      1,
		HungTasks:           []string{"mysqld"},
	}
	if counts := w.Take(); !reflect.DeepEqual(counts, want) {
		t.Fatalf("got %+v, want %+v", counts, want)
	}
}
