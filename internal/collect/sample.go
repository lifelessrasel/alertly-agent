package collect

import (
	"context"
	"time"

	"github.com/lifelessrasel/alertly-agent/internal/security"
)

// Sample is one entry in a metrics batch.
type Sample struct {
	RecordedAt       string           `json:"recorded_at"`
	CPU              *CPU             `json:"cpu,omitempty"`
	Load             []float64        `json:"load,omitempty"`
	Memory           *Memory          `json:"memory,omitempty"`
	Swap             *Swap            `json:"swap,omitempty"`
	DiskIO           *DiskIO          `json:"disk_io,omitempty"`
	Network          *Network         `json:"network,omitempty"`
	ProcessCount     uint64           `json:"process_count"`
	UptimeSeconds    uint64           `json:"uptime_seconds"`
	Filesystems      []Filesystem     `json:"filesystems"`
	Interfaces       []Interface      `json:"interfaces,omitempty"`
	Services         []ServiceState   `json:"services"`
	FailedUnits      []string         `json:"failed_units"`
	DetectedServices []string         `json:"detected_services"`
	TopProcesses     []TopProcess     `json:"top_processes"`
	ListeningPorts   []ListeningPort  `json:"listening_ports"`
	Updates          *Updates         `json:"updates,omitempty"`
	Security         *security.Counts `json:"security,omitempty"`
	Docker           *DockerState     `json:"docker,omitempty"`

	takenAt time.Time
}

// TakenAt is when the sample was collected.
func (s Sample) TakenAt() time.Time {
	return s.takenAt
}

// WithTakenAt restores the collection time of a sample read back from disk.
func (s Sample) WithTakenAt(at time.Time) Sample {
	s.takenAt = at
	return s
}

// Collector builds metrics samples.
type Collector struct {
	system    *System
	services  *Services
	processes *Processes
	docker    *Docker
	security  *security.Watcher
	updates   *UpdateChecker
}

// NewCollector creates a collector. Docker and the security watcher are nil when disabled.
func NewCollector(docker *Docker, watcher *security.Watcher) *Collector {
	return &Collector{system: NewSystem(), services: NewServices(), processes: NewProcesses(), docker: docker, security: watcher, updates: NewUpdateChecker()}
}

// Sample collects every metric. watches are the services the server asked to report.
func (c *Collector) Sample(ctx context.Context, watches []Watch) Sample {
	now := time.Now()
	cpu, diskIO, network, interfaces := c.system.Rates()
	memory, swap := MemoryUsage()
	topProcesses, listeningPorts := c.processes.Top()

	sample := Sample{
		RecordedAt:       now.UTC().Format(time.RFC3339),
		CPU:              cpu,
		Load:             Load(),
		Memory:           memory,
		Swap:             swap,
		DiskIO:           diskIO,
		Network:          network,
		ProcessCount:     ProcessCount(),
		UptimeSeconds:    Uptime(),
		Filesystems:      Filesystems(),
		Interfaces:       interfaces,
		Services:         c.services.Collect(ctx, watches),
		FailedUnits:      FailedUnits(ctx),
		DetectedServices: DetectedServices(ctx),
		TopProcesses:     topProcesses,
		ListeningPorts:   listeningPorts,
		Updates:          c.updates.Collect(ctx),
		takenAt:          now,
	}

	if c.security != nil {
		sample.Security = c.security.Take()
	}
	if c.docker != nil {
		sample.Docker = c.docker.Collect(ctx)
	}

	return sample
}
