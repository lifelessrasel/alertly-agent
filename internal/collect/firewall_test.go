package collect

import (
	"context"
	"reflect"
	"testing"
)

func TestDetectFirewall(t *testing.T) {
	probe := func(files map[string]string, active map[string]bool) firewallProbe {
		return firewallProbe{
			exists:   func(path string) bool { _, ok := files[path]; return ok },
			readFile: func(path string) string { return files[path] },
			isActive: func(_ context.Context, unit string) bool { return active[unit] },
		}
	}

	cases := map[string]struct {
		probe firewallProbe
		want  *Firewall
	}{
		"ufw on":         {probe(map[string]string{"/etc/ufw/ufw.conf": "# comment\nENABLED=yes\nLOGLEVEL=low\n"}, nil), &Firewall{Tool: "ufw", Active: true}},
		"ufw off":        {probe(map[string]string{"/etc/ufw/ufw.conf": "ENABLED=no\n"}, nil), &Firewall{Tool: "ufw", Active: false}},
		"firewalld on":   {probe(map[string]string{"/usr/bin/firewall-cmd": ""}, map[string]bool{"firewalld": true}), &Firewall{Tool: "firewalld", Active: true}},
		"nftables off":   {probe(map[string]string{"/etc/nftables.conf": ""}, nil), &Firewall{Tool: "nftables", Active: false}},
		"iptables saved": {probe(map[string]string{"/etc/iptables/rules.v4": ""}, map[string]bool{"netfilter-persistent": true}), &Firewall{Tool: "iptables", Active: true}},
		"none":           {probe(map[string]string{}, nil), nil},
	}

	for name, tc := range cases {
		if got := detectFirewall(context.Background(), tc.probe); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: got %+v, want %+v", name, got, tc.want)
		}
	}
}
