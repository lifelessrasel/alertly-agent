package main

import (
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/lifelessrasel/alertly-agent/internal/collect"
	"github.com/lifelessrasel/alertly-agent/internal/security"
)

var rewriteFixture = flag.Bool("update", false, "rewrite testdata/payloads.json")

func ptr[T any](value T) *T {
	return &value
}

// TestPayloadsMatchFixture keeps testdata/payloads.json in sync with the agent's JSON. The Alertly
// app's test suite posts that file to the API, so a renamed field fails on one side or the other.
func TestPayloadsMatchFixture(t *testing.T) {
	heartbeat := collect.HostInfo{
		Hostname:         "web-1",
		IPAddress:        "203.0.113.10",
		IPv6Address:      "2001:db8::10",
		OS:               collect.OSInfo{ID: "ubuntu", Name: "Ubuntu 24.04.1 LTS", Version: "24.04"},
		Kernel:           "6.8.0-45-generic",
		Architecture:     "amd64",
		CPUCores:         4,
		MemoryTotalBytes: 8589934592,
		UptimeSeconds:    7200,
		AgentVersion:     "0.1.0",
		Timezone:         "Europe/Berlin",
		ServerTime:       "2026-01-01T12:00:00+01:00",
	}

	sample := collect.Sample{
		RecordedAt:    "2026-01-01T11:00:00Z",
		CPU:           &collect.CPU{Percent: 12.5, Cores: []float64{20, 5}},
		Load:          []float64{0.5, 0.4, 0.3},
		Memory:        &collect.Memory{TotalBytes: 8589934592, UsedBytes: 2147483648, AvailableBytes: 6442450944},
		Swap:          &collect.Swap{TotalBytes: 1073741824, UsedBytes: 0},
		DiskIO:        &collect.DiskIO{ReadBytesPerSec: 4096, WriteBytesPerSec: 8192, UtilizationPercent: 1.5},
		Network:       &collect.Network{RxBytesPerSec: 1000, TxBytesPerSec: 2000},
		ProcessCount:  150,
		UptimeSeconds: 7200,
		Filesystems: []collect.Filesystem{
			{Mount: "/", Device: "/dev/sda1", FSType: "ext4", TotalBytes: 85899345920, UsedBytes: 21474836480, InodesTotal: 5242880, InodesUsed: 250000, ReadOnly: ptr(false)},
		},
		Interfaces: []collect.Interface{
			{Name: "eth0", MAC: "02:42:ac:11:00:02", Addresses: []string{"203.0.113.10/24", "2001:db8::10/64"}, RxBytesPerSec: 1000, TxBytesPerSec: 2000},
		},
		Services: []collect.ServiceState{
			{Kind: "systemd", Name: "nginx", State: "running", ProcessCount: ptr(uint64(5)), CPUPercent: ptr(0.8), MemoryBytes: ptr(uint64(52428800))},
			{Kind: "process", Name: "php-fpm", State: "stopped"},
		},
		FailedUnits:      []string{"certbot.service"},
		DetectedServices: []string{"nginx", "mysql"},
		TopProcesses: []collect.TopProcess{
			{Name: "php-fpm8.3", User: "www-data", Count: 6, CPUPercent: 7.5, MemoryBytes: 314572800},
			{Name: "mysqld", User: "mysql", Count: 1, CPUPercent: 2.1, MemoryBytes: 838860800},
		},
		ListeningPorts: []collect.ListeningPort{
			{Protocol: "tcp", Port: 22, Address: "0.0.0.0"},
			{Protocol: "tcp", Port: 3306, Address: "127.0.0.1", Process: "mysqld"},
			{Protocol: "udp", Port: 53, Address: "::"},
		},
		Zombies:  &collect.Zombies{Count: 2, Parents: []string{"php-fpm"}},
		Firewall: &collect.Firewall{Tool: "ufw", Active: true},
		Updates:  &collect.Updates{RebootRequired: true, Pending: ptr(12), Security: ptr(3)},
		Security: &security.Counts{
			FailedLogins: 4, OOMKills: 1, OOMKilled: []string{"mysqld"},
			SudoCommands: 3, SudoUsers: []string{"deploy"}, NewUsers: []string{"backup"}, AdminGrants: []string{"backup:sudo"},
			DiskErrors: 2, DiskErrorDevices: []string{"sdb"}, ReadOnlyFilesystems: []string{"sdb1"},
			Crashes: 1, Crashed: []string{"php-fpm8.3"}, HardwareErrors: 0, HungTasks: []string{"mysqld"},
		},
		Docker: &collect.DockerState{
			Available: true,
			Version:   "27.3.1",
			Containers: []collect.Container{
				{
					Name: "app", ID: "4f9d8c1e2b3a", Image: "ghcr.io/example/app:latest", State: "running", Health: "healthy",
					ExitCode: ptr(0), RestartPolicy: "unless-stopped", RestartCount: ptr(uint64(1)), StartedAt: "2026-01-01T10:00:00Z",
					CPUPercent: ptr(3.5), MemoryBytes: ptr(uint64(134217728)), MemoryLimitBytes: ptr(uint64(536870912)),
					RxBytesPerSec: ptr(uint64(300)), TxBytesPerSec: ptr(uint64(400)),
				},
				{Name: "worker", ID: "9a8b7c6d5e4f", Image: "redis:7", State: "exited", ExitCode: ptr(137), RestartPolicy: "no", RestartCount: ptr(uint64(0))},
			},
		},
		Integrations: &collect.Integrations{
			MySQL: &collect.MySQLStatus{
				Health: collect.Health{Up: true}, Connections: 140, MaxConnections: 151, Running: 6,
				QueriesPerSecond: ptr(85.5), SlowQueries: ptr(uint64(2)), UptimeSeconds: 864000,
			},
			Postgres: &collect.PostgresStatus{Health: collect.Health{Error: "psql: error: connection to server at \"127.0.0.1\", port 5432 failed: Connection refused"}},
			Redis: &collect.RedisStatus{
				Health: collect.Health{Up: true}, UsedMemoryBytes: 52428800, MaxMemoryBytes: 268435456, Clients: 12,
				OpsPerSecond: 340, HitRatePercent: ptr(97.5), EvictedKeys: ptr(uint64(0)),
			},
			Nginx: &collect.NginxStatus{Health: collect.Health{Up: true}, Active: 25, Reading: 0, Writing: 3, Waiting: 22, RequestsPerSecond: ptr(42.5), Dropped: ptr(uint64(0))},
			PHPFPM: &collect.PHPFPMStatus{
				Health: collect.Health{Up: true}, Pool: "www", Active: 10, Idle: 0, Total: 10, ListenQueue: 4,
				MaxChildrenReached: ptr(uint64(2)), SlowRequests: ptr(uint64(0)),
			},
		},
	}

	payloads := map[string]any{
		"heartbeat": heartbeat,
		"metrics":   map[string]any{"samples": []collect.Sample{sample}},
	}

	got, err := json.MarshalIndent(payloads, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')

	if *rewriteFixture {
		if err := os.WriteFile("testdata/payloads.json", got, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	want, err := os.ReadFile("testdata/payloads.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("payloads changed; run `go test . -update` and the Laravel contract test\n%s", got)
	}
}
