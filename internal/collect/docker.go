package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DockerState is the Docker section of a metrics sample.
type DockerState struct {
	Available  bool        `json:"available"`
	Version    string      `json:"version,omitempty"`
	Containers []Container `json:"containers"`
}

// Container is the reported state of one container.
type Container struct {
	Name             string   `json:"name"`
	ID               string   `json:"id,omitempty"`
	Image            string   `json:"image,omitempty"`
	State            string   `json:"state"`
	Health           string   `json:"health,omitempty"`
	ExitCode         *int     `json:"exit_code,omitempty"`
	RestartPolicy    string   `json:"restart_policy,omitempty"`
	RestartCount     *uint64  `json:"restart_count,omitempty"`
	StartedAt        string   `json:"started_at,omitempty"`
	CPUPercent       *float64 `json:"cpu_percent,omitempty"`
	MemoryBytes      *uint64  `json:"memory_bytes,omitempty"`
	MemoryLimitBytes *uint64  `json:"memory_limit_bytes,omitempty"`
	RxBytesPerSec    *uint64  `json:"rx_bytes_per_sec,omitempty"`
	TxBytesPerSec    *uint64  `json:"tx_bytes_per_sec,omitempty"`
}

const maxContainers = 200

// Docker reads container state from the Docker Engine API over its Unix socket.
type Docker struct {
	http     *http.Client
	mu       sync.Mutex
	networks map[string]containerNetwork
}

type containerNetwork struct {
	at     time.Time
	rx, tx uint64
}

// NewDocker creates a client for the given socket path, usually /var/run/docker.sock.
func NewDocker(socket string) *Docker {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConnsPerHost: 8,
	}

	return &Docker{
		http:     &http.Client{Transport: transport, Timeout: 15 * time.Second},
		networks: map[string]containerNetwork{},
	}
}

// Collect returns Docker's version and containers, or Available false when the daemon is unreachable.
func (d *Docker) Collect(ctx context.Context) *DockerState {
	var version struct {
		Version string `json:"Version"`
	}
	if err := d.get(ctx, "/version", &version); err != nil {
		return &DockerState{Available: false, Containers: []Container{}}
	}

	var list []struct {
		ID    string   `json:"Id"`
		Names []string `json:"Names"`
		Image string   `json:"Image"`
		State string   `json:"State"`
	}
	if err := d.get(ctx, "/containers/json?all=1", &list); err != nil {
		return &DockerState{Available: false, Version: truncate(version.Version, 32), Containers: []Container{}}
	}
	if len(list) > maxContainers {
		list = list[:maxContainers]
	}

	containers := make([]Container, len(list))
	var wait sync.WaitGroup
	limit := make(chan struct{}, 8)
	for i, item := range list {
		name := item.ID
		if len(item.Names) > 0 {
			name = strings.TrimPrefix(item.Names[0], "/")
		}
		containers[i] = Container{
			Name:  truncate(name, 128),
			ID:    truncate(item.ID, 64),
			Image: truncate(item.Image, 255),
			State: containerState(item.State),
		}

		wait.Add(1)
		limit <- struct{}{}
		go func(container *Container) {
			defer wait.Done()
			defer func() { <-limit }()
			d.inspect(ctx, container)
			if container.State == "running" {
				d.stats(ctx, container)
			}
		}(&containers[i])
	}
	wait.Wait()

	d.forgetRemoved(containers)

	return &DockerState{Available: true, Version: truncate(version.Version, 32), Containers: containers}
}

func (d *Docker) inspect(ctx context.Context, container *Container) {
	var details struct {
		RestartCount uint64 `json:"RestartCount"`
		State        struct {
			Status    string `json:"Status"`
			ExitCode  int    `json:"ExitCode"`
			StartedAt string `json:"StartedAt"`
			Health    *struct {
				Status string `json:"Status"`
			} `json:"Health"`
		} `json:"State"`
		HostConfig struct {
			RestartPolicy struct {
				Name string `json:"Name"`
			} `json:"RestartPolicy"`
		} `json:"HostConfig"`
	}
	if err := d.get(ctx, "/containers/"+url.PathEscape(container.ID)+"/json", &details); err != nil {
		return
	}

	container.State = containerState(details.State.Status)
	if details.State.Health != nil && containerHealth(details.State.Health.Status) {
		container.Health = details.State.Health.Status
	}
	if code := details.State.ExitCode; code >= -1 && code <= 255 {
		container.ExitCode = &code
	}
	container.RestartPolicy = restartPolicy(details.HostConfig.RestartPolicy.Name)
	container.RestartCount = &details.RestartCount
	if started, err := time.Parse(time.RFC3339Nano, details.State.StartedAt); err == nil && started.Year() > 1 {
		container.StartedAt = started.UTC().Format(time.RFC3339)
	}
}

type dockerStats struct {
	CPUStats    cpuStats `json:"cpu_stats"`
	PreCPUStats cpuStats `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Limit uint64            `json:"limit"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
	Networks map[string]struct {
		RxBytes uint64 `json:"rx_bytes"`
		TxBytes uint64 `json:"tx_bytes"`
	} `json:"networks"`
}

type cpuStats struct {
	CPUUsage struct {
		TotalUsage  uint64   `json:"total_usage"`
		PercpuUsage []uint64 `json:"percpu_usage"`
	} `json:"cpu_usage"`
	SystemCPUUsage uint64 `json:"system_cpu_usage"`
	OnlineCPUs     uint64 `json:"online_cpus"`
}

func (d *Docker) stats(ctx context.Context, container *Container) {
	var stats dockerStats
	if err := d.get(ctx, "/containers/"+url.PathEscape(container.ID)+"/stats?stream=false", &stats); err != nil {
		return
	}

	if percent, ok := containerCPUPercent(stats); ok {
		container.CPUPercent = &percent
	}

	if stats.MemoryStats.Usage > 0 {
		memory := containerMemory(stats.MemoryStats.Usage, stats.MemoryStats.Stats)
		container.MemoryBytes = &memory
		if limit := stats.MemoryStats.Limit; limit > 0 {
			container.MemoryLimitBytes = &limit
		}
	}

	if stats.Networks != nil {
		var rx, tx uint64
		for _, network := range stats.Networks {
			rx += network.RxBytes
			tx += network.TxBytes
		}

		now := time.Now()
		d.mu.Lock()
		previous, ok := d.networks[container.ID]
		d.networks[container.ID] = containerNetwork{at: now, rx: rx, tx: tx}
		d.mu.Unlock()

		if ok {
			elapsed := now.Sub(previous.at).Seconds()
			rxRate, txRate := rate(previous.rx, rx, elapsed), rate(previous.tx, tx, elapsed)
			container.RxBytesPerSec, container.TxBytesPerSec = &rxRate, &txRate
		}
	}
}

// containerCPUPercent matches `docker stats`, then divides by the CPU count so 100% means every core is busy.
func containerCPUPercent(stats dockerStats) (float64, bool) {
	cpuDelta := float64(delta(stats.PreCPUStats.CPUUsage.TotalUsage, stats.CPUStats.CPUUsage.TotalUsage))
	systemDelta := float64(delta(stats.PreCPUStats.SystemCPUUsage, stats.CPUStats.SystemCPUUsage))
	if stats.PreCPUStats.SystemCPUUsage == 0 || systemDelta <= 0 {
		return 0, false
	}

	return clampPercent(cpuDelta / systemDelta * 100), true
}

// containerMemory subtracts the page cache, like `docker stats` does on cgroup v1 and v2.
func containerMemory(usage uint64, stats map[string]uint64) uint64 {
	cache, ok := stats["inactive_file"]
	if !ok {
		cache = stats["total_inactive_file"]
	}
	if cache > usage {
		return usage
	}

	return usage - cache
}

func (d *Docker) forgetRemoved(containers []Container) {
	current := make(map[string]bool, len(containers))
	for _, container := range containers {
		current[container.ID] = true
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	for id := range d.networks {
		if !current[id] {
			delete(d.networks, id)
		}
	}
}

func (d *Docker) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}

	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("docker %s: status %d", path, resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

func containerState(state string) string {
	switch state {
	case "created", "running", "paused", "restarting", "removing", "exited", "dead":
		return state
	default:
		return "dead"
	}
}

func containerHealth(health string) bool {
	return health == "starting" || health == "healthy" || health == "unhealthy"
}

func restartPolicy(policy string) string {
	switch policy {
	case "always", "unless-stopped", "on-failure":
		return policy
	default:
		return "no"
	}
}
