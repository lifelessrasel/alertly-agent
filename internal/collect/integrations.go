package collect

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IntegrationConfig names the databases and web servers to check. Each one is off until it is configured in
// /etc/alertly/agent.yml, and credentials never leave the server.
type IntegrationConfig struct {
	MySQLHost, MySQLUser, MySQLPassword                      string
	PostgresHost, PostgresUser, PostgresPassword, PostgresDB string
	RedisAddress, RedisPassword                              string
	NginxStatusURL, PHPFPMStatusURL                          string
}

// Enabled reports whether any integration is configured.
func (c IntegrationConfig) Enabled() bool {
	return c.MySQLUser != "" || c.PostgresUser != "" || c.RedisAddress != "" || c.NginxStatusURL != "" || c.PHPFPMStatusURL != ""
}

// Integrations is the latest state of each configured database and web server.
type Integrations struct {
	MySQL    *MySQLStatus    `json:"mysql,omitempty"`
	Postgres *PostgresStatus `json:"postgres,omitempty"`
	Redis    *RedisStatus    `json:"redis,omitempty"`
	Nginx    *NginxStatus    `json:"nginx,omitempty"`
	PHPFPM   *PHPFPMStatus   `json:"php_fpm,omitempty"`
}

// Health is shared by every integration: whether it answered, and a short reason when it didn't.
type Health struct {
	Up    bool   `json:"up"`
	Error string `json:"error,omitempty"`
}

type MySQLStatus struct {
	Health
	Connections      uint64   `json:"connections"`
	MaxConnections   uint64   `json:"max_connections"`
	Running          uint64   `json:"running"`
	QueriesPerSecond *float64 `json:"queries_per_second,omitempty"`
	SlowQueries      *uint64  `json:"slow_queries,omitempty"`
	UptimeSeconds    uint64   `json:"uptime_seconds"`
}

type PostgresStatus struct {
	Health
	Connections         uint64  `json:"connections"`
	MaxConnections      uint64  `json:"max_connections"`
	Active              uint64  `json:"active"`
	LongestQuerySeconds uint64  `json:"longest_query_seconds"`
	Deadlocks           *uint64 `json:"deadlocks,omitempty"`
	DatabaseSizeBytes   uint64  `json:"database_size_bytes"`
}

type RedisStatus struct {
	Health
	UsedMemoryBytes uint64   `json:"used_memory_bytes"`
	MaxMemoryBytes  uint64   `json:"max_memory_bytes"`
	Clients         uint64   `json:"clients"`
	OpsPerSecond    uint64   `json:"ops_per_second"`
	HitRatePercent  *float64 `json:"hit_rate_percent,omitempty"`
	EvictedKeys     *uint64  `json:"evicted_keys,omitempty"`
}

type NginxStatus struct {
	Health
	Active            uint64   `json:"active"`
	Reading           uint64   `json:"reading"`
	Writing           uint64   `json:"writing"`
	Waiting           uint64   `json:"waiting"`
	RequestsPerSecond *float64 `json:"requests_per_second,omitempty"`
	Dropped           *uint64  `json:"dropped,omitempty"`
}

type PHPFPMStatus struct {
	Health
	Pool               string  `json:"pool,omitempty"`
	Active             uint64  `json:"active"`
	Idle               uint64  `json:"idle"`
	Total              uint64  `json:"total"`
	ListenQueue        uint64  `json:"listen_queue"`
	MaxChildrenReached *uint64 `json:"max_children_reached,omitempty"`
	SlowRequests       *uint64 `json:"slow_requests,omitempty"`
}

const (
	integrationTimeout = 5 * time.Second
	maxErrorLength     = 160
)

// IntegrationChecker queries the configured integrations. Counters are turned into rates or into the change
// since the previous check, so a restart or the first check reports nothing instead of a misleading jump.
type IntegrationChecker struct {
	config IntegrationConfig
	client *http.Client

	mu       sync.Mutex
	previous map[string]counterReading
}

type counterReading struct {
	value uint64
	at    time.Time
}

// NewIntegrationChecker returns nil when nothing is configured.
func NewIntegrationChecker(config IntegrationConfig) *IntegrationChecker {
	if !config.Enabled() {
		return nil
	}

	return &IntegrationChecker{
		config:   config,
		client:   &http.Client{Timeout: integrationTimeout},
		previous: map[string]counterReading{},
	}
}

// Collect checks every configured integration in parallel.
func (c *IntegrationChecker) Collect(ctx context.Context) *Integrations {
	if c == nil {
		return nil
	}

	var result Integrations
	var wg sync.WaitGroup
	check := func(enabled bool, fn func()) {
		if enabled {
			wg.Add(1)
			go func() {
				defer wg.Done()
				fn()
			}()
		}
	}

	check(c.config.MySQLUser != "", func() { result.MySQL = c.mysql(ctx) })
	check(c.config.PostgresUser != "", func() { result.Postgres = c.postgres(ctx) })
	check(c.config.RedisAddress != "", func() { result.Redis = c.redis(ctx) })
	check(c.config.NginxStatusURL != "", func() { result.Nginx = c.nginx(ctx) })
	check(c.config.PHPFPMStatusURL != "", func() { result.PHPFPM = c.phpFPM(ctx) })
	wg.Wait()

	return &result
}

// delta is how much a counter grew since the previous reading, or nil on the first reading and after a reset.
func (c *IntegrationChecker) delta(key string, value uint64, now time.Time) (*uint64, time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	previous, ok := c.previous[key]
	c.previous[key] = counterReading{value: value, at: now}
	if !ok || value < previous.value {
		return nil, 0
	}
	grown := value - previous.value

	return &grown, now.Sub(previous.at)
}

func (c *IntegrationChecker) rate(key string, value uint64, now time.Time) *float64 {
	grown, elapsed := c.delta(key, value, now)
	if grown == nil || elapsed <= 0 {
		return nil
	}
	perSecond := float64(*grown) / elapsed.Seconds()

	return &perSecond
}

func (c *IntegrationChecker) mysql(ctx context.Context) *MySQLStatus {
	query := "SHOW GLOBAL STATUS WHERE Variable_name IN ('Threads_connected','Threads_running','Questions','Slow_queries','Uptime'); SHOW GLOBAL VARIABLES WHERE Variable_name = 'max_connections'"
	args := []string{"--batch", "--skip-column-names", "--connect-timeout=5", "--host=" + orDefault(c.config.MySQLHost, "127.0.0.1"), "--user=" + c.config.MySQLUser, "--execute=" + query}
	output, err := runWithPassword(ctx, "MYSQL_PWD", c.config.MySQLPassword, firstCommand("mysql", "mariadb"), args...)
	if err != nil {
		return &MySQLStatus{Health: down(err)}
	}

	values := parseTabbedValues(output)
	now := time.Now()
	status := &MySQLStatus{
		Health:         Health{Up: true},
		Connections:    values["Threads_connected"],
		MaxConnections: values["max_connections"],
		Running:        values["Threads_running"],
		UptimeSeconds:  values["Uptime"],
	}
	status.QueriesPerSecond = c.rate("mysql.questions", values["Questions"], now)
	status.SlowQueries, _ = c.delta("mysql.slow", values["Slow_queries"], now)

	return status
}

func (c *IntegrationChecker) postgres(ctx context.Context) *PostgresStatus {
	query := `SELECT (SELECT count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'),
		current_setting('max_connections')::int,
		(SELECT count(*) FROM pg_stat_activity WHERE state = 'active' AND backend_type = 'client backend'),
		coalesce((SELECT extract(epoch FROM max(now() - query_start))::bigint FROM pg_stat_activity WHERE state = 'active' AND backend_type = 'client backend'), 0),
		(SELECT coalesce(sum(deadlocks), 0) FROM pg_stat_database),
		pg_database_size(current_database())`
	args := []string{"--no-psqlrc", "--no-align", "--tuples-only", "--field-separator=|", "--host=" + orDefault(c.config.PostgresHost, "127.0.0.1"), "--username=" + c.config.PostgresUser, "--dbname=" + orDefault(c.config.PostgresDB, "postgres"), "--command=" + query}
	output, err := runWithPassword(ctx, "PGPASSWORD", c.config.PostgresPassword, "psql", args...)
	if err != nil {
		return &PostgresStatus{Health: down(err)}
	}

	fields := strings.Split(strings.TrimSpace(output), "|")
	if len(fields) != 6 {
		return &PostgresStatus{Health: Health{Error: "unexpected reply from psql"}}
	}
	numbers := make([]uint64, len(fields))
	for i, field := range fields {
		numbers[i], _ = strconv.ParseUint(strings.TrimSpace(field), 10, 64)
	}

	status := &PostgresStatus{
		Health:              Health{Up: true},
		Connections:         numbers[0],
		MaxConnections:      numbers[1],
		Active:              numbers[2],
		LongestQuerySeconds: numbers[3],
		DatabaseSizeBytes:   numbers[5],
	}
	status.Deadlocks, _ = c.delta("postgres.deadlocks", numbers[4], time.Now())

	return status
}

func (c *IntegrationChecker) redis(ctx context.Context) *RedisStatus {
	info, err := redisInfo(ctx, c.config.RedisAddress, c.config.RedisPassword)
	if err != nil {
		return &RedisStatus{Health: down(err)}
	}

	values := parseRedisInfo(info)
	now := time.Now()
	status := &RedisStatus{
		Health:          Health{Up: true},
		UsedMemoryBytes: values["used_memory"],
		MaxMemoryBytes:  values["maxmemory"],
		Clients:         values["connected_clients"],
		OpsPerSecond:    values["instantaneous_ops_per_sec"],
	}
	status.EvictedKeys, _ = c.delta("redis.evicted", values["evicted_keys"], now)
	hits, _ := c.delta("redis.hits", values["keyspace_hits"], now)
	misses, _ := c.delta("redis.misses", values["keyspace_misses"], now)
	if hits != nil && misses != nil && *hits+*misses > 0 {
		rate := float64(*hits) / float64(*hits+*misses) * 100
		status.HitRatePercent = &rate
	}

	return status
}

func (c *IntegrationChecker) nginx(ctx context.Context) *NginxStatus {
	body, err := c.get(ctx, c.config.NginxStatusURL)
	if err != nil {
		return &NginxStatus{Health: down(err)}
	}

	parsed, ok := parseNginxStatus(body)
	if !ok {
		return &NginxStatus{Health: Health{Error: "not an nginx stub_status page"}}
	}

	now := time.Now()
	status := &NginxStatus{Health: Health{Up: true}, Active: parsed.active, Reading: parsed.reading, Writing: parsed.writing, Waiting: parsed.waiting}
	status.RequestsPerSecond = c.rate("nginx.requests", parsed.requests, now)
	status.Dropped, _ = c.delta("nginx.dropped", parsed.accepts-min(parsed.handled, parsed.accepts), now)

	return status
}

func (c *IntegrationChecker) phpFPM(ctx context.Context) *PHPFPMStatus {
	url := c.config.PHPFPMStatusURL
	switch {
	case strings.Contains(url, "json"):
	case strings.Contains(url, "?"):
		url += "&json"
	default:
		url += "?json"
	}
	body, err := c.get(ctx, url)
	if err != nil {
		return &PHPFPMStatus{Health: down(err)}
	}

	var reply struct {
		Pool               string `json:"pool"`
		ListenQueue        uint64 `json:"listen queue"`
		Idle               uint64 `json:"idle processes"`
		Active             uint64 `json:"active processes"`
		Total              uint64 `json:"total processes"`
		MaxChildrenReached uint64 `json:"max children reached"`
		SlowRequests       uint64 `json:"slow requests"`
	}
	if err := json.Unmarshal([]byte(body), &reply); err != nil {
		return &PHPFPMStatus{Health: Health{Error: "not a php-fpm status page"}}
	}

	now := time.Now()
	status := &PHPFPMStatus{Health: Health{Up: true}, Pool: truncate(reply.Pool, 64), Active: reply.Active, Idle: reply.Idle, Total: reply.Total, ListenQueue: reply.ListenQueue}
	status.MaxChildrenReached, _ = c.delta("php-fpm.max-children", reply.MaxChildrenReached, now)
	status.SlowRequests, _ = c.delta("php-fpm.slow", reply.SlowRequests, now)

	return status
}

func (c *IntegrationChecker) get(ctx context.Context, url string) (string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", errors.New("invalid status URL")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return "", errors.New("status page not reachable")
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status page answered %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))

	return string(body), err
}

// runWithPassword passes the password in the environment, so it never shows up in the process list.
func runWithPassword(ctx context.Context, variable, password, name string, args ...string) (string, error) {
	if name == "" {
		return "", errors.New("client is not installed")
	}

	ctx, cancel := context.WithTimeout(ctx, integrationTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), variable+"="+password)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return "", errors.New(firstLine(message))
		}
		return "", err
	}

	return string(output), nil
}

func redisInfo(ctx context.Context, address, password string) (string, error) {
	dialer := net.Dialer{Timeout: integrationTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return "", errors.New("not reachable")
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(integrationTimeout))

	reader := bufio.NewReader(conn)
	if password != "" {
		if _, err := conn.Write(respCommand("AUTH", password)); err != nil {
			return "", err
		}
		reply, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		if !strings.HasPrefix(reply, "+") {
			return "", errors.New("authentication failed")
		}
	}

	if _, err := conn.Write(respCommand("INFO")); err != nil {
		return "", err
	}
	header, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if strings.HasPrefix(header, "-") {
		return "", errors.New(truncate(strings.TrimSpace(header[1:]), maxErrorLength))
	}
	size, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(header, "$")))
	if !strings.HasPrefix(header, "$") || err != nil || size < 0 || size > 1024*1024 {
		return "", errors.New("unexpected reply")
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(reader, body); err != nil {
		return "", err
	}

	return string(body), nil
}

func respCommand(parts ...string) []byte {
	var command strings.Builder
	fmt.Fprintf(&command, "*%d\r\n", len(parts))
	for _, part := range parts {
		fmt.Fprintf(&command, "$%d\r\n%s\r\n", len(part), part)
	}

	return []byte(command.String())
}

// parseRedisInfo reads the numeric "key:value" lines of an INFO reply.
func parseRedisInfo(info string) map[string]uint64 {
	values := map[string]uint64{}
	for _, line := range strings.Split(info, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		if number, err := strconv.ParseUint(value, 10, 64); err == nil {
			values[key] = number
		}
	}

	return values
}

// parseTabbedValues reads "name<TAB>value" lines from the mysql client.
func parseTabbedValues(output string) map[string]uint64 {
	values := map[string]uint64{}
	for _, line := range strings.Split(output, "\n") {
		name, value, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		if number, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64); err == nil {
			values[name] = number
		}
	}

	return values
}

type nginxStubStatus struct {
	active, accepts, handled, requests, reading, writing, waiting uint64
}

// parseNginxStatus reads the stub_status page:
//
//	Active connections: 2
//	server accepts handled requests
//	 10 10 20
//	Reading: 0 Writing: 1 Waiting: 1
func parseNginxStatus(body string) (nginxStubStatus, bool) {
	var status nginxStubStatus
	lines := strings.Split(strings.TrimSpace(body), "\n")
	if len(lines) < 4 {
		return status, false
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(lines[0]), "Active connections: %d", &status.active); err != nil {
		return status, false
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(lines[2]), "%d %d %d", &status.accepts, &status.handled, &status.requests); err != nil {
		return status, false
	}
	if _, err := fmt.Sscanf(strings.TrimSpace(lines[3]), "Reading: %d Writing: %d Waiting: %d", &status.reading, &status.writing, &status.waiting); err != nil {
		return status, false
	}

	return status, true
}

func down(err error) Health {
	return Health{Error: truncate(firstLine(err.Error()), maxErrorLength)}
}

func firstLine(text string) string {
	line, _, _ := strings.Cut(text, "\n")
	return strings.TrimSpace(line)
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}

func firstCommand(names ...string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}

	return ""
}
