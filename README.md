# Alertly agent

The Linux server agent for [Alertly](https://alertly.net). It reports CPU (in total and per core), memory, disk, network, the busiest processes, listening ports, the state of watched systemd services and processes, and Docker containers to your Alertly dashboard. It also counts failed SSH logins and out-of-memory kills in the authentication and kernel logs; only the counts and the names of killed processes are sent, never log lines.

It's written in Go with no third-party dependencies, and runs as an unprivileged `alertly` user under systemd.

## Install

Add a server in your Alertly dashboard and run the install command it shows:

```bash
curl -fsSL https://alertly.net/agent/install.sh | sudo bash -s -- --token=alr_...
```

To see what the agent collects without sending anything, run `sudo -u alertly alertly-agent --once`. Its log is available with `journalctl -u alertly-agent`.

## Updates

The installer adds an `alertly-agent-update` systemd timer that runs `alertly-agent --update` as root once a day. It asks the dashboard for the current version and, when this one is older, downloads the new binary from `download_url` in `/etc/alertly/agent.yml` (never from an address the API returns), checks its SHA-256 checksum, makes sure it runs, replaces `/usr/local/bin/alertly-agent` and restarts the service. Install with `--no-auto-update` to update by running the install command again instead.

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
