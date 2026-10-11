package collect

import (
	"context"
	"strings"
	"time"
)

// Firewall is the host firewall the agent found and whether it is on. The agent runs without root,
// so it reads ufw's settings file and asks systemd about firewalld and nftables instead of the rules.
type Firewall struct {
	Tool   string `json:"tool"`
	Active bool   `json:"active"`
}

const (
	firewallInterval = 5 * time.Minute
	firewallTimeout  = 5 * time.Second
)

// FirewallChecker remembers the last answer between samples.
type FirewallChecker struct {
	checkedAt time.Time
	last      *Firewall
	probe     firewallProbe
}

type firewallProbe struct {
	exists   func(path string) bool
	readFile func(path string) string
	isActive func(ctx context.Context, unit string) bool
}

// NewFirewallChecker creates a checker that looks on the first sample.
func NewFirewallChecker() *FirewallChecker {
	return &FirewallChecker{probe: firewallProbe{exists: fileExists, readFile: readFile, isActive: unitIsActive}}
}

// Collect returns the firewall state, or nil when no supported firewall is installed.
func (f *FirewallChecker) Collect(ctx context.Context) *Firewall {
	if time.Since(f.checkedAt) >= firewallInterval {
		f.checkedAt = time.Now()
		f.last = detectFirewall(ctx, f.probe)
	}

	return f.last
}

func detectFirewall(ctx context.Context, probe firewallProbe) *Firewall {
	if probe.exists("/etc/ufw/ufw.conf") {
		return &Firewall{Tool: "ufw", Active: ufwEnabled(probe.readFile("/etc/ufw/ufw.conf"))}
	}
	if probe.exists("/usr/sbin/firewalld") || probe.exists("/usr/bin/firewall-cmd") {
		return &Firewall{Tool: "firewalld", Active: probe.isActive(ctx, "firewalld")}
	}
	if probe.exists("/etc/nftables.conf") || probe.exists("/etc/sysconfig/nftables.conf") {
		return &Firewall{Tool: "nftables", Active: probe.isActive(ctx, "nftables")}
	}
	if probe.exists("/etc/iptables/rules.v4") {
		return &Firewall{Tool: "iptables", Active: probe.isActive(ctx, "netfilter-persistent")}
	}

	return nil
}

// ufwEnabled reads ENABLED=yes from /etc/ufw/ufw.conf, which "ufw enable" and "ufw disable" rewrite.
func ufwEnabled(conf string) bool {
	for _, line := range strings.Split(conf, "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && strings.TrimSpace(key) == "ENABLED" {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(value), `"'`), "yes")
		}
	}

	return false
}

func unitIsActive(ctx context.Context, unit string) bool {
	output, code, err := runFor(ctx, firewallTimeout, "systemctl", "is-active", unit)

	return err == nil && code == 0 && strings.TrimSpace(output) == "active"
}
