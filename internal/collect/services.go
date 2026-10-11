package collect

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Watch is a service the server asked the agent to report on.
type Watch struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// ServiceState is the reported state of a watched service.
type ServiceState struct {
	Kind         string   `json:"kind"`
	Name         string   `json:"name"`
	State        string   `json:"state"`
	ProcessCount *uint64  `json:"process_count,omitempty"`
	CPUPercent   *float64 `json:"cpu_percent,omitempty"`
	MemoryBytes  *uint64  `json:"memory_bytes,omitempty"`
}

// clockTicks is USER_HZ, which is 100 on every mainstream Linux architecture.
const clockTicks = 100

// Services reports on watched systemd units and processes, keeping CPU counters between samples.
type Services struct {
	lastAt     time.Time
	unitCPU    map[string]uint64
	processCPU map[string]uint64
	pageSize   uint64
}

// NewServices creates a services collector.
func NewServices() *Services {
	return &Services{
		lastAt:     time.Now(),
		unitCPU:    map[string]uint64{},
		processCPU: map[string]uint64{},
		pageSize:   uint64(os.Getpagesize()),
	}
}

// HasSystemd reports whether systemctl can be used.
func HasSystemd() bool {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return false
	}
	_, err := os.Stat("/run/systemd/system")

	return err == nil
}

// Collect returns the state of each watched service.
func (s *Services) Collect(ctx context.Context, watches []Watch) []ServiceState {
	now := time.Now()
	elapsed := now.Sub(s.lastAt).Seconds()
	s.lastAt = now

	var processes []processInfo
	states := make([]ServiceState, 0, len(watches))
	for _, watch := range watches {
		switch watch.Kind {
		case "systemd":
			states = append(states, s.unit(ctx, watch.Name, elapsed))
		case "process":
			if processes == nil {
				processes = listProcesses(s.pageSize)
			}
			states = append(states, s.process(watch.Name, processes, elapsed))
		}
	}

	return states
}

func (s *Services) unit(ctx context.Context, name string, elapsed float64) ServiceState {
	state := ServiceState{Kind: "systemd", Name: name, State: "missing"}
	if !HasSystemd() {
		return state
	}

	output, err := run(ctx, "systemctl", "show", "--no-pager",
		"--property=LoadState,ActiveState,TasksCurrent,MemoryCurrent,CPUUsageNSec", "--", unitName(name))
	if err != nil {
		return state
	}

	properties := parseProperties(output)
	state.State = unitState(properties["LoadState"], properties["ActiveState"])
	if state.State != "running" {
		delete(s.unitCPU, name)
		return state
	}

	state.ProcessCount = optionalUint(properties["TasksCurrent"])
	state.MemoryBytes = optionalUint(properties["MemoryCurrent"])
	if usage := optionalUint(properties["CPUUsageNSec"]); usage != nil {
		if previous, ok := s.unitCPU[name]; ok && elapsed > 0 {
			percent := float64(delta(previous, *usage)) / (elapsed * 1e9) * 100
			state.CPUPercent = &percent
		}
		s.unitCPU[name] = *usage
	}

	return state
}

func (s *Services) process(name string, processes []processInfo, elapsed float64) ServiceState {
	state := ServiceState{Kind: "process", Name: name, State: "stopped"}

	var count, memory, ticks uint64
	for _, process := range processes {
		if matchesProcess(process, name) {
			count++
			memory += process.rssBytes
			ticks += process.cpuTicks
		}
	}

	if count == 0 {
		delete(s.processCPU, name)
		return state
	}

	state.State = "running"
	state.ProcessCount = &count
	state.MemoryBytes = &memory
	if previous, ok := s.processCPU[name]; ok && elapsed > 0 {
		percent := float64(delta(previous, ticks)) / clockTicks / elapsed * 100
		state.CPUPercent = &percent
	}
	s.processCPU[name] = ticks

	return state
}

// FailedUnits lists systemd units in the failed state, or nil without systemd.
func FailedUnits(ctx context.Context) []string {
	if !HasSystemd() {
		return nil
	}
	output, err := run(ctx, "systemctl", "list-units", "--state=failed", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil
	}

	units := []string{}
	for _, name := range firstColumn(output) {
		if len(units) < 100 {
			units = append(units, truncate(name, 255))
		}
	}

	return units
}

var interestingServices = []string{
	"nginx", "apache2", "httpd", "caddy", "traefik", "haproxy", "varnish", "frankenphp", "lsws", "openresty",
	"mysql", "mariadb", "postgresql", "mongod", "redis", "valkey", "keydb", "memcached", "clickhouse",
	"elasticsearch", "opensearch", "meilisearch", "typesense", "influxdb", "rabbitmq", "kafka", "zookeeper", "nats",
	"php", "supervisor", "docker", "containerd", "podman", "kubelet", "k3s", "cron", "crond", "ssh", "sshd",
	"fail2ban", "postfix", "dovecot", "exim4", "named", "bind9", "unbound", "pdns", "minio", "grafana",
	"prometheus", "node_exporter", "jenkins", "gitlab", "pm2", "horizon", "octane", "reverb", "netdata", "wg-quick",
}

// DetectedServices lists running systemd services worth watching, for the dashboard to suggest.
func DetectedServices(ctx context.Context) []string {
	if !HasSystemd() {
		return nil
	}
	output, err := run(ctx, "systemctl", "list-units", "--type=service", "--state=running", "--plain", "--no-legend", "--no-pager")
	if err != nil {
		return nil
	}

	detected := []string{}
	for _, unit := range firstColumn(output) {
		name := strings.TrimSuffix(unit, ".service")
		if len(detected) < 50 && isInterestingService(name) {
			detected = append(detected, truncate(name, 100))
		}
	}

	return detected
}

func isInterestingService(name string) bool {
	base, _, _ := strings.Cut(name, "@")
	for _, prefix := range interestingServices {
		if base == prefix || strings.HasPrefix(base, prefix) {
			return true
		}
	}

	return false
}

// unitName adds ".service" when the name has no unit type suffix.
func unitName(name string) string {
	for _, suffix := range []string{".service", ".socket", ".timer", ".target", ".mount", ".path", ".scope", ".slice"} {
		if strings.HasSuffix(name, suffix) {
			return name
		}
	}

	return name + ".service"
}

func unitState(loadState, activeState string) string {
	if loadState == "not-found" || loadState == "" {
		return "missing"
	}

	switch activeState {
	case "active", "reloading", "activating", "refreshing":
		return "running"
	case "failed":
		return "failed"
	default:
		return "stopped"
	}
}

func parseProperties(output string) map[string]string {
	properties := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			properties[key] = strings.TrimSpace(value)
		}
	}

	return properties
}

// optionalUint parses a systemd numeric property. "[not set]" and the "infinity" sentinel are nil.
func optionalUint(value string) *uint64 {
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil || parsed == ^uint64(0) {
		return nil
	}

	return &parsed
}

func firstColumn(output string) []string {
	var values []string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(strings.TrimLeft(line, "● *"))
		if len(fields) > 0 {
			values = append(values, fields[0])
		}
	}

	return values
}

type processInfo struct {
	comm     string
	exe      string
	cpuTicks uint64
	rssBytes uint64
}

func listProcesses(pageSize uint64) []processInfo {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	processes := make([]processInfo, 0, len(entries))
	for _, entry := range entries {
		if !isPID(entry.Name()) {
			continue
		}
		dir := "/proc/" + entry.Name()
		stat := readFile(dir + "/stat")
		if stat == "" {
			continue
		}

		comm, ticks := parseProcStat(stat)
		process := processInfo{comm: comm, cpuTicks: ticks}
		if fields := strings.Fields(readFile(dir + "/statm")); len(fields) > 1 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			process.rssBytes = pages * pageSize
		}
		if cmdline := readFile(dir + "/cmdline"); cmdline != "" {
			first, _, _ := strings.Cut(cmdline, "\x00")
			process.exe = filepath.Base(first)
		}
		processes = append(processes, process)
	}

	return processes
}

// parseProcStat returns the command name and user plus system CPU ticks from /proc/<pid>/stat.
// The name is in parentheses and may itself contain spaces and parentheses.
func parseProcStat(stat string) (string, uint64) {
	start, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if start < 0 || end < start {
		return "", 0
	}

	fields := strings.Fields(stat[end+1:])
	if len(fields) < 13 {
		return stat[start+1 : end], 0
	}
	user, _ := strconv.ParseUint(fields[11], 10, 64)
	system, _ := strconv.ParseUint(fields[12], 10, 64)

	return stat[start+1 : end], user + system
}

// matchesProcess compares against the kernel name, which is cut to 15 characters, and the executable name.
func matchesProcess(process processInfo, name string) bool {
	return process.comm == truncate(name, 15) || process.exe == name
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	output, err := exec.CommandContext(ctx, name, args...).Output()

	return string(output), err
}
