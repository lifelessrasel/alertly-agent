# Alertly agent

The Linux server agent for [Alertly](https://alertly.net). It reports CPU (in total and per core), memory, disk, network, the busiest processes, listening ports, the state of watched systemd services and processes, and Docker containers to your Alertly dashboard. It also counts failed SSH logins and out-of-memory kills in the authentication and kernel logs; only the counts and the names of killed processes are sent, never log lines.

It's written in Go with no third-party dependencies, and runs as an unprivileged `alertly` user under systemd.

## Install

Add a server in your Alertly dashboard and run the install command it shows:

```bash
curl -fsSL https://alertly.net/agent/install.sh | sudo bash -s -- --token=alr_...
```

To see what the agent collects without sending anything, run `sudo -u alertly alertly-agent --once`. Its log is available with `journalctl -u alertly-agent`.

## Databases and web servers

The agent can also report MySQL or MariaDB, PostgreSQL, Redis, nginx and PHP-FPM. Each one is off until you add its lines to `/etc/alertly/agent.yml` and run `sudo systemctl restart alertly-agent`. Credentials stay in that file on the server; passwords are passed to the database clients in the environment, never on the command line, and only numbers and a short error are sent.

```yaml
# MySQL or MariaDB, through the mysql client.
# Create the user with: CREATE USER 'alertly'@'localhost' IDENTIFIED BY '...'; GRANT PROCESS ON *.* TO 'alertly'@'localhost';
mysql_user: alertly
mysql_password: "..."
mysql_host: 127.0.0.1

# PostgreSQL, through psql.
# Create the user with: CREATE ROLE alertly LOGIN PASSWORD '...'; GRANT pg_monitor TO alertly;
postgres_user: alertly
postgres_password: "..."
postgres_host: 127.0.0.1
postgres_database: postgres

# Redis, spoken to directly.
redis: 127.0.0.1:6379
redis_password: "..."

# nginx's stub_status page and PHP-FPM's pm.status_path, both kept private to the server.
nginx_status_url: http://127.0.0.1/nginx_status
php_fpm_status_url: http://127.0.0.1/fpm-status
```

An nginx block that serves both status pages to the server only:

```nginx
server {
    listen 127.0.0.1:80;
    server_name 127.0.0.1;
    location = /nginx_status { stub_status; allow 127.0.0.1; deny all; }
    location = /fpm-status { include fastcgi_params; fastcgi_param SCRIPT_FILENAME $fastcgi_script_name; fastcgi_pass unix:/run/php/php-fpm.sock; allow 127.0.0.1; deny all; }
}
```

Set `pm.status_path = /fpm-status` in the PHP-FPM pool and reload it. Run `sudo -u alertly alertly-agent --once` to check what the agent sees.

## Updates

The installer adds an `alertly-agent-update` systemd timer that runs `alertly-agent --update` as root once a day. It asks the dashboard for the current version and, when this one is older, downloads the new binary from `download_url` in `/etc/alertly/agent.yml` (never from an address the API returns), checks its SHA-256 checksum, makes sure it runs, replaces `/usr/local/bin/alertly-agent` and restarts the service. Install with `--no-auto-update` to update by running the install command again instead.

## Controlled from the dashboard

Every heartbeat and metrics reply carries the reporting intervals, whether the server is paused, the services to watch and a `collect` map. Kinds of data set to `false` there (`processes`, `ports`, `logs`, `updates`, `firewall`, `docker`, `integrations`) are left out of every sample; kinds it doesn't mention stay on. When the site admin holds updates, the version endpoint returns no version and the update timer does nothing.

## Offline buffering

Measurements that can't be sent are kept for up to 23 hours and written to `/var/lib/alertly/pending.json` (systemd's `StateDirectory`), so they survive restarts. While a server is paused on the dashboard, the agent only sends heartbeats.

## Build

```bash
go test ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.version=0.2.0" -o alertly-agent .
```

Pushing a tag such as `v0.2.0` builds Linux binaries for amd64, arm64 and armv7, with SHA-256 checksums, and attaches them to a GitHub release. To build the same files locally, run `./build.sh 0.2.0`; they're written to `dist/`.

The Alertly install script downloads `alertly-agent-linux-{amd64,arm64,armv7}` and its `.sha256` file from https://github.com/lifelessrasel/alertly-agent/releases/latest/download.

`testdata/payloads.json` is the contract with the dashboard: the Alertly app's test suite posts it to the API. After changing a payload, run `go test . -update` and copy the file to the app's `tests/Fixtures/agent-payloads.json`.
