//go:build !windows

package portx

import (
	"context"
	"strings"
	"testing"
)

func TestEvalLinux(t *testing.T) {
	cases := []struct {
		name, ufw, nft, ipt string
		st                  Status
		title               string
	}{
		{"ufw allows", "Status: active\n\nTo                         Action      From\n--                         ------      ----\n8080/tcp                   ALLOW       Anywhere\n", "", "", OK, "ufw allows"},
		{"ufw denies", "Status: active\n8080                       DENY        Anywhere\n", "", "", Bad, "ufw denies"},
		{"ufw no rule", "Status: active\n22/tcp ALLOW Anywhere\n", "", "", Bad, "no rule"},
		{"ufw off, nothing loaded", "Status: inactive\n", "", "", OK, "No firewall rules"},
		{"nft drop with rule", "", "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n  tcp dport { 22, 8080 } accept\n }\n}", "", OK, "mentions"},
		{"nft drop without rule", "", "table inet filter {\n chain input {\n  type filter hook input priority 0; policy drop;\n  tcp dport 22 accept\n }\n}", "", Bad, "drops incoming"},
		{"iptables accept policy", "", "", "-P INPUT ACCEPT\n-P FORWARD DROP\n", OK, "by default"},
		{"iptables drop with rule", "", "", "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT\n", OK, "mentions"},
		{"iptables 18080 isn't 8080", "", "", "-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 18080 -j ACCEPT\n", Bad, "drops incoming"},
	}
	for _, c := range cases {
		v := EvalLinux(c.ufw, c.nft, c.ipt, 8080, "tcp")
		if v.Status != c.st || !strings.Contains(v.Title, c.title) {
			t.Errorf("%s: %s %q", c.name, v.Status, v.Title)
		}
	}
}

func TestLinuxFirewallNeedsRoot(t *testing.T) {
	old := geteuid
	defer func() { geteuid = old }()
	geteuid = func() int { return 1000 }
	if v := linuxFirewall(context.Background(), 8080, "tcp"); v.Status != Unknown || !strings.Contains(v.Fix, "sudo") {
		t.Errorf("%+v", v)
	}
}
