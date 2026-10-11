// Command alertly-agent reports server metrics and service and container state to Alertly.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/lifelessrasel/alertly-agent/internal/client"
	"github.com/lifelessrasel/alertly-agent/internal/collect"
	"github.com/lifelessrasel/alertly-agent/internal/config"
	"github.com/lifelessrasel/alertly-agent/internal/security"
	"github.com/lifelessrasel/alertly-agent/internal/update"
)

// version is set at build time with -ldflags "-X main.version=1.2.3".
var version = "0.0.0-dev"

func main() {
	configPath := flag.String("config", "/etc/alertly/agent.yml", "path to the agent configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	once := flag.Bool("once", false, "print one heartbeat and metrics sample as JSON and exit")
	selfUpdate := flag.Bool("update", false, "install the latest version if this one is outdated, then restart the service")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	log.SetFlags(0)

	if *once {
		printOnce(*configPath)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *selfUpdate {
		if err := runUpdate(ctx, cfg); err != nil {
			log.Fatalf("update: %v", err)
		}
		return
	}

	log.Printf("alertly-agent %s reporting to %s", version, cfg.Endpoint)
	newAgent(cfg).run(ctx)
	log.Print("stopped")
}

// printOnce collects without sending, which helps when debugging an install.
func printOnce(configPath string) {
	endpoint := ""
	var docker *collect.Docker
	if cfg, err := config.Load(configPath); err == nil {
		endpoint = cfg.Endpoint
		if cfg.Docker {
			docker = collect.NewDocker(dockerSocket)
		}
	}

	var integrations *collect.IntegrationChecker
	if cfg, err := config.Load(configPath); err == nil {
		integrations = collect.NewIntegrationChecker(integrationConfig(cfg))
	}
	collector := collect.NewCollector(docker, nil, integrations)
	time.Sleep(2 * time.Second)

	output, _ := json.MarshalIndent(map[string]any{
		"heartbeat": collect.Host(version, endpoint),
		"sample":    collector.Sample(context.Background(), nil),
	}, "", "  ")
	fmt.Println(string(output))
}

// runUpdate replaces this binary with the latest version and restarts the agent service. It runs as root
// from the alertly-agent-update timer. Binaries are only downloaded from the configured URL, never from
// one the API returns.
func runUpdate(ctx context.Context, cfg config.Config) error {
	var reply struct {
		LatestVersion string `json:"latest_version"`
	}
	if err := client.New(cfg.Endpoint, cfg.Token, version).Get(ctx, "version", &reply); err != nil {
		return err
	}
	if reply.LatestVersion == "" || update.SameVersion(reply.LatestVersion, version) {
		log.Printf("alertly-agent %s is up to date", version)
		return nil
	}

	binPath, err := os.Executable()
	if err != nil {
		return err
	}
	if binPath, err = filepath.EvalSymlinks(binPath); err != nil {
		return err
	}

	downloadURL := cfg.DownloadURL
	if downloadURL == "" {
		downloadURL = update.DefaultDownloadURL
	}

	log.Printf("updating alertly-agent from %s to %s", version, reply.LatestVersion)
	if err := update.Install(ctx, downloadURL, reply.LatestVersion, binPath); err != nil {
		return err
	}

	if output, err := exec.CommandContext(ctx, "systemctl", "try-restart", "alertly-agent").CombinedOutput(); err != nil {
		return fmt.Errorf("installed %s but could not restart the service: %v: %s", reply.LatestVersion, err, output)
	}
	log.Printf("updated to %s", reply.LatestVersion)

	return nil
}

const dockerSocket = "/var/run/docker.sock"

// serverConfig is returned by the heartbeat and metrics endpoints.
type serverConfig struct {
	Paused             bool            `json:"paused"`
	HeartbeatInterval  int             `json:"heartbeat_interval"`
	MetricsInterval    int             `json:"metrics_interval"`
	LatestAgentVersion string          `json:"latest_agent_version"`
	Watch              []collect.Watch `json:"watch"`
}

type agent struct {
	cfg       config.Config
	api       *client.Client
	collector *collect.Collector
	security  *security.Watcher
	stateFile string

	heartbeatEvery time.Duration
	metricsEvery   time.Duration
	paused         bool
	watch          []collect.Watch
	pending        []collect.Sample
	batchSize      int
	warnedVersion  bool
}

const (
	maxBatchSize      = 120
	maxPendingSamples = 2000
	maxSampleAge      = 23 * time.Hour
)

func newAgent(cfg config.Config) *agent {
	var docker *collect.Docker
	if cfg.Docker {
		docker = collect.NewDocker(dockerSocket)
	}

	var watcher *security.Watcher
	if cfg.Logs {
		watcher = security.NewWatcher()
	}

	// systemd sets STATE_DIRECTORY to the writable directory named by StateDirectory= in the unit.
	stateFile := ""
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		stateFile = filepath.Join(dir, "pending.json")
	}

	return &agent{
		cfg:            cfg,
		api:            client.New(cfg.Endpoint, cfg.Token, version),
		collector:      collect.NewCollector(docker, watcher, collect.NewIntegrationChecker(integrationConfig(cfg))),
		security:       watcher,
		stateFile:      stateFile,
		heartbeatEvery: time.Minute,
		metricsEvery:   time.Minute,
		batchSize:      maxBatchSize,
	}
}

func (a *agent) run(ctx context.Context) {
	a.pending = loadPending(a.stateFile, time.Now().Add(-maxSampleAge))
	defer func() { savePending(a.stateFile, a.pending) }()

	if a.security != nil {
		go a.security.Run(ctx)
	}

	backoff := 10 * time.Second
	for !a.heartbeat(ctx) {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 5*time.Minute)
	}

	heartbeat := time.NewTimer(a.heartbeatEvery)
	metrics := time.NewTimer(min(a.metricsEvery, 15*time.Second))
	defer heartbeat.Stop()
	defer metrics.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-heartbeat.C:
			a.heartbeat(ctx)
			heartbeat.Reset(a.heartbeatEvery)
		case <-metrics.C:
			a.collectAndSend(ctx)
			metrics.Reset(a.metricsEvery)
		}
	}
}

func (a *agent) heartbeat(ctx context.Context) bool {
	var reply serverConfig
	if err := a.api.Post(ctx, "heartbeat", collect.Host(version, a.cfg.Endpoint), &reply); err != nil {
		a.logError("heartbeat", err)
		return false
	}
	a.apply(reply)

	return true
}

// collectAndSend takes a sample and sends everything pending. While the server is paused nothing is
// collected and buffered samples are dropped, since the dashboard would discard them anyway.
func (a *agent) collectAndSend(ctx context.Context) {
	if a.paused {
		a.pending = nil
		if a.security != nil {
			a.security.Take()
		}
		return
	}

	for i := range a.pending {
		a.pending[i].TopProcesses, a.pending[i].ListeningPorts = nil, nil
	}
	a.pending = append(a.pending, a.collector.Sample(ctx, a.watch))

	cutoff := time.Now().Add(-maxSampleAge)
	for len(a.pending) > 0 && (a.pending[0].TakenAt().Before(cutoff) || len(a.pending) > maxPendingSamples) {
		a.pending = a.pending[1:]
	}

	for len(a.pending) > 0 && ctx.Err() == nil {
		batch := a.pending[:min(a.batchSize, len(a.pending))]

		var reply serverConfig
		err := a.api.Post(ctx, "metrics", map[string]any{"samples": batch}, &reply)

		var status *client.StatusError
		switch {
		case err == nil:
			a.pending = a.pending[len(batch):]
			a.batchSize = maxBatchSize
			a.apply(reply)
		case errors.As(err, &status) && status.Status == http.StatusRequestEntityTooLarge && a.batchSize > 1:
			a.batchSize /= 2
			continue
		case errors.As(err, &status) && status.Status == http.StatusUnprocessableEntity:
			log.Printf("metrics: dropping %d rejected samples: %s", len(batch), status.Body)
			a.pending = a.pending[len(batch):]
			continue
		default:
			a.logError("metrics", err)
			savePending(a.stateFile, a.pending)
			return
		}
	}
	savePending(a.stateFile, a.pending)
}

func (a *agent) apply(reply serverConfig) {
	if reply.HeartbeatInterval >= 10 {
		a.heartbeatEvery = time.Duration(reply.HeartbeatInterval) * time.Second
	}
	if reply.MetricsInterval >= 10 {
		a.metricsEvery = time.Duration(reply.MetricsInterval) * time.Second
	}
	if reply.Paused != a.paused {
		a.paused = reply.Paused
		if a.paused {
			log.Print("monitoring is paused on the dashboard; only heartbeats are sent")
		} else {
			log.Print("monitoring resumed")
		}
	}
	a.watch = reply.Watch

	if reply.LatestAgentVersion != "" && !update.SameVersion(reply.LatestAgentVersion, version) && !a.warnedVersion {
		a.warnedVersion = true
		log.Printf("version %s is available; it installs automatically when auto-update is on, or rerun the install command from the dashboard", reply.LatestAgentVersion)
	}
}

// loadPending reads samples buffered before a restart, dropping ones older than cutoff.
func loadPending(path string, cutoff time.Time) []collect.Sample {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var stored []collect.Sample
	if err := json.Unmarshal(data, &stored); err != nil {
		log.Printf("buffer: ignoring unreadable %s: %v", path, err)
		return nil
	}

	pending := make([]collect.Sample, 0, len(stored))
	for _, sample := range stored {
		takenAt, err := time.Parse(time.RFC3339, sample.RecordedAt)
		if err != nil || takenAt.Before(cutoff) {
			continue
		}
		pending = append(pending, sample.WithTakenAt(takenAt))
	}
	if len(pending) > maxPendingSamples {
		pending = pending[len(pending)-maxPendingSamples:]
	}
	if len(pending) > 0 {
		log.Printf("buffer: resending %d samples saved before the last restart", len(pending))
	}

	return pending
}

// savePending writes unsent samples so a restart doesn't lose them, or removes the file when there are none.
func savePending(path string, pending []collect.Sample) {
	if path == "" {
		return
	}
	if len(pending) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("buffer: %v", err)
		}
		return
	}

	data, err := json.Marshal(pending)
	if err != nil {
		log.Printf("buffer: %v", err)
		return
	}
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, data, 0o600); err != nil {
		log.Printf("buffer: %v", err)
		return
	}
	if err := os.Rename(temporary, path); err != nil {
		log.Printf("buffer: %v", err)
	}
}

func (a *agent) logError(action string, err error) {
	var status *client.StatusError
	if errors.As(err, &status) && status.Status == http.StatusUnauthorized {
		log.Printf("%s: the agent token was rejected; reinstall the agent from the dashboard", action)
		return
	}
	log.Printf("%s: %v", action, err)
}

func integrationConfig(cfg config.Config) collect.IntegrationConfig {
	return collect.IntegrationConfig{
		MySQLHost: cfg.MySQLHost, MySQLUser: cfg.MySQLUser, MySQLPassword: cfg.MySQLPassword,
		PostgresHost: cfg.PostgresHost, PostgresUser: cfg.PostgresUser, PostgresPassword: cfg.PostgresPassword, PostgresDB: cfg.PostgresDB,
		RedisAddress: cfg.Redis, RedisPassword: cfg.RedisPassword,
		NginxStatusURL: cfg.NginxStatusURL, PHPFPMStatusURL: cfg.PHPFPMStatusURL,
	}
}
