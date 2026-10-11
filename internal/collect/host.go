// Package collect gathers host information and metrics from /proc, /sys, systemd, and Docker.
package collect

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// OSInfo identifies the Linux distribution.
type OSInfo struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

// HostInfo is the heartbeat payload.
type HostInfo struct {
	Hostname         string `json:"hostname"`
	IPAddress        string `json:"ip_address,omitempty"`
	OS               OSInfo `json:"os"`
	Kernel           string `json:"kernel,omitempty"`
	Architecture     string `json:"architecture,omitempty"`
	CPUCores         int    `json:"cpu_cores,omitempty"`
	MemoryTotalBytes uint64 `json:"memory_total_bytes,omitempty"`
	UptimeSeconds    uint64 `json:"uptime_seconds"`
	AgentVersion     string `json:"agent_version"`
	Timezone         string `json:"timezone,omitempty"`
	ServerTime       string `json:"server_time"`
}

var osIDPattern = regexp.MustCompile(`^[a-z0-9._-]+$`)

// Host describes the machine the agent runs on. endpoint is used to find the outbound IP address.
func Host(version, endpoint string) HostInfo {
	hostname, _ := os.Hostname()
	memory, _ := readMeminfo()

	info := HostInfo{
		Hostname:         hostname,
		IPAddress:        outboundIP(endpoint),
		OS:               readOSRelease(),
		Kernel:           strings.TrimSpace(readFile("/proc/sys/kernel/osrelease")),
		Architecture:     runtime.GOARCH,
		CPUCores:         runtime.NumCPU(),
		MemoryTotalBytes: memory["MemTotal"],
		UptimeSeconds:    uptimeSeconds(),
		AgentVersion:     version,
		Timezone:         timezone(),
		ServerTime:       time.Now().Format(time.RFC3339),
	}

	return info
}

func readOSRelease() OSInfo {
	file, err := os.Open("/etc/os-release")
	if err != nil {
		return OSInfo{}
	}
	defer file.Close()

	values := map[string]string{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if ok {
			values[key] = strings.Trim(value, `"'`)
		}
	}

	info := OSInfo{Name: values["PRETTY_NAME"], Version: values["VERSION_ID"]}
	if id := strings.ToLower(values["ID"]); osIDPattern.MatchString(id) {
		info.ID = id
	}
	if info.Name == "" {
		info.Name = values["NAME"]
	}
	if len(info.Version) > 64 {
		info.Version = info.Version[:64]
	}

	return info
}

// outboundIP is the local address used to reach the API, which is usually the public or primary address.
func outboundIP(endpoint string) string {
	host := "1.1.1.1"
	if parsed, err := url.Parse(endpoint); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}

	conn, err := net.DialTimeout("udp", net.JoinHostPort(host, "443"), 3*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	if addr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return addr.IP.String()
	}

	return ""
}

// timezone is the IANA name of the system timezone, e.g. "Europe/Berlin", or "" when unknown.
func timezone() string {
	if name := strings.TrimSpace(readFile("/etc/timezone")); name != "" {
		if _, err := time.LoadLocation(name); err == nil {
			return name
		}
	}

	target, err := filepath.EvalSymlinks("/etc/localtime")
	if err != nil {
		return ""
	}
	if _, name, ok := strings.Cut(target, "zoneinfo/"); ok {
		if _, err := time.LoadLocation(name); err == nil {
			return name
		}
	}

	return ""
}

func uptimeSeconds() uint64 {
	fields := strings.Fields(readFile("/proc/uptime"))
	if len(fields) == 0 {
		return 0
	}
	seconds, _ := strconv.ParseFloat(fields[0], 64)

	return uint64(seconds)
}

func readFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	return string(data)
}
