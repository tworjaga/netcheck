package cli

import (
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

type vcase struct {
	name string
	st   ui.Status
	msg  string
	want ui.Status
	has  string
}

func checkCases(t *testing.T, cases []vcase) {
	t.Helper()
	for _, c := range cases {
		if c.st != c.want || !strings.Contains(c.msg, c.has) {
			t.Errorf("%s: got (%v, %q), want (%v, …%q…)", c.name, c.st, c.msg, c.want, c.has)
		}
	}
}

func TestIPv6Verdict(t *testing.T) {
	type R = probe.IPv6Result
	run := func(name string, r R, want ui.Status, has string) vcase {
		st, msg := ipv6Verdict(r)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("works, preferred", R{Address: "2001:db8::1", Reachable: true, V6Ms: 12, V4Ms: 11, DNSAAAA: true, Preferred: true}, ui.OK, "preferred"),
		run("works, v4 preferred", R{Reachable: true, V6Ms: 12, V4Ms: 11, DNSAAAA: true}, ui.OK, "prefers IPv4"),
		run("ipv4 only", R{V4Ms: 11}, ui.Skip, "IPv4-only"),
		run("broken v6", R{Address: "2001:db8::1", V4Ms: 11, DNSAAAA: true}, ui.Warn, "time out"),
		run("slow v6", R{Reachable: true, V6Ms: 90, V4Ms: 11, DNSAAAA: true, Preferred: true}, ui.Warn, "slower"),
		run("no AAAA", R{Reachable: true, V6Ms: 12, V4Ms: 11}, ui.Warn, "DNS server"),
		run("offline", R{}, ui.Bad, "Couldn't reach"),
	})
}

func TestCaptiveVerdict(t *testing.T) {
	ok := probe.CaptiveProbe{Intact: true, Status: 204}
	redir := probe.CaptiveProbe{Status: 302, Redirect: "login.example"}
	altered := probe.CaptiveProbe{Status: 200}
	dead := probe.CaptiveProbe{Error: "timeout"}
	run := func(name string, ps []probe.CaptiveProbe, want ui.Status, has string) vcase {
		st, msg := captiveVerdict(probe.CaptiveResult{Probes: ps})
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("clean", []probe.CaptiveProbe{ok, ok, ok}, ui.OK, "No captive portal"),
		run("clean with one blocked", []probe.CaptiveProbe{ok, dead, ok}, ui.OK, "No captive portal"),
		run("portal", []probe.CaptiveProbe{redir, redir, redir}, ui.Bad, "login.example"),
		run("portal without redirect", []probe.CaptiveProbe{altered, altered, dead}, ui.Bad, "captive portal or filter"),
		run("one rewritten", []probe.CaptiveProbe{ok, altered, ok}, ui.Warn, "1 of 3"),
		run("offline", []probe.CaptiveProbe{dead, dead, dead}, ui.Bad, "offline"),
	})
}

func TestTLSVerdict(t *testing.T) {
	good := probe.TLSProbe{Host: "a", OK: true, Version: "TLS 1.3"}
	type R = probe.TLSResult
	run := func(name string, r R, want ui.Status, has string) vcase {
		st, msg, _ := tlsVerdict(r)
		return vcase{name, st, msg, want, has}
	}
	inspected := good
	inspected.Inspector = "Avast Web/Mail Shield Root"
	v12 := good
	v12.Version = "TLS 1.2"
	checkCases(t, []vcase{
		run("healthy", R{Probes: []probe.TLSProbe{good, good}, ClockChecked: true, SkewSeconds: 0.4}, ui.OK, "within 1 s"),
		run("clock far off", R{Probes: []probe.TLSProbe{{Host: "a", Problem: "expired"}}, ClockChecked: true, SkewSeconds: -86400 * 3}, ui.Bad, "3 d behind"),
		run("clock a bit off", R{Probes: []probe.TLSProbe{good}, ClockChecked: true, SkewSeconds: 95}, ui.Warn, "1 min 35 s ahead"),
		run("intercepted", R{Probes: []probe.TLSProbe{good, {Host: "b", Problem: "untrusted", Issuer: "EvilProxy"}}, ClockChecked: true}, ui.Bad, `"EvilProxy"`),
		run("wrong name", R{Probes: []probe.TLSProbe{{Host: "b", Problem: "name"}}}, ui.Bad, "another site"),
		run("antivirus", R{Probes: []probe.TLSProbe{inspected}, ClockChecked: true}, ui.Warn, "Avast"),
		run("downgraded", R{Probes: []probe.TLSProbe{v12, v12}, ClockChecked: true}, ui.Warn, "TLS 1.2"),
		run("offline", R{Probes: []probe.TLSProbe{{Problem: "network"}, {Problem: "network"}}}, ui.Bad, "Couldn't make any HTTPS"),
		run("clock unchecked", R{Probes: []probe.TLSProbe{good}}, ui.OK, "certificates check out."),
	})
}

func TestLeakVerdict(t *testing.T) {
	isp := probe.Egress{IP: "203.0.113.53", ASN: "AS64500", Org: "HOMEISP"}
	google := probe.Egress{IP: "74.125.0.9", ASN: "AS15169", Org: "GOOGLE"}
	other := probe.Egress{IP: "198.51.100.9", ASN: "AS64999", Org: "SOMEDNS"}
	home := probe.IPInfo{IP: "203.0.113.7", ASN: "AS64500", ISP: "HOMEISP"}
	vpnExit := probe.IPInfo{IP: "192.0.2.7", ASN: "AS64777", ISP: "VPNCO"}
	run := func(name string, r probe.LeakResult, want ui.Status, has string) vcase {
		st, msg := leakVerdict(r)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("no vpn, isp dns", probe.LeakResult{Public: home, Resolvers: []probe.Egress{isp}}, ui.OK, "your ISP's (HOMEISP)"),
		run("no vpn, google", probe.LeakResult{Public: home, Resolvers: []probe.Egress{google}}, ui.OK, "Google Public DNS"),
		run("no vpn, other", probe.LeakResult{Public: home, Resolvers: []probe.Egress{other}}, ui.OK, "SOMEDNS"),
		run("vpn, leak to isp", probe.LeakResult{VPN: []string{"wg0"}, Public: vpnExit, Resolvers: []probe.Egress{isp}}, ui.Bad, "DNS leak"),
		run("vpn, dns through vpn", probe.LeakResult{VPN: []string{"wg0"}, Public: vpnExit, Resolvers: []probe.Egress{{IP: "192.0.2.53", ASN: "AS64777"}}}, ui.OK, "through the VPN (VPNCO)"),
		run("vpn, public dns", probe.LeakResult{VPN: []string{"wg0"}, Public: vpnExit, Resolvers: []probe.Egress{google}}, ui.OK, "Google"),
		run("vpn, unknown exit", probe.LeakResult{VPN: []string{"wg0"}, Resolvers: []probe.Egress{isp}}, ui.Warn, "Couldn't confirm"),
		run("nothing seen", probe.LeakResult{}, ui.Skip, "Couldn't see"),
	})
}

func TestDNSSECVerdict(t *testing.T) {
	type R = probe.DNSSECResult
	valid := R{Server: "1.1.1.1", Answered: true, AD: true, Rejects: true, RejectKnown: true}
	plain := R{Server: "192.168.1.1", Answered: true, RejectKnown: true}
	run := func(name string, sys, ctl R, want ui.Status, has string) vcase {
		st, msg := dnssecVerdict(sys, ctl)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("validating", valid, valid, ui.OK, "refused"),
		run("AD only", R{Server: "x", Answered: true, AD: true}, valid, ui.OK, "verified"),
		run("not validating", plain, valid, ui.Warn, "doesn't check DNSSEC"),
		run("stripped", plain, plain, ui.Warn, "stripping"),
		run("lying AD", R{Server: "x", Answered: true, AD: true, RejectKnown: true}, valid, ui.Warn, "broken signature through"),
		run("sys silent", R{Server: "x"}, valid, ui.Warn, "didn't answer"),
		run("all silent", R{Server: "x"}, R{}, ui.Bad, "No DNS server"),
	})
}

func TestMTUVerdict(t *testing.T) {
	type R = probe.MTUResult
	run := func(name string, r R, want ui.Status, has string) vcase {
		st, msg := mtuVerdict(r)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("full", R{MTU: 1500}, ui.OK, "1500"),
		run("pppoe", R{MTU: 1492, Signalled: true}, ui.OK, "PPPoE"),
		run("vpn", R{MTU: 1420, Signalled: true}, ui.OK, "VPN"),
		run("tiny", R{MTU: 1280, Signalled: true}, ui.Warn, "unusually small"),
		run("black hole", R{MTU: 1492}, ui.Warn, "black hole"),
		run("no icmp", R{Error: probe.ErrNoICMP.Error()}, ui.Skip, "elevation"),
		run("blocked", R{Target: "1.1.1.1", Error: probe.ErrICMPBlocked.Error()}, ui.Skip, "doesn't answer ping"),
	})
}

func TestDHCPVerdict(t *testing.T) {
	type R = probe.DHCPResult
	one := probe.DHCPServer{ServerID: "192.168.1.1", Offered: "192.168.1.50"}
	rogue := probe.DHCPServer{ServerID: "192.168.0.1", Offered: "192.168.0.10"}
	run := func(name string, r R, gw string, want ui.Status, has string) vcase {
		st, msg := dhcpVerdict(r, gw, false)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("one, the router", R{Servers: []probe.DHCPServer{one}}, "192.168.1.1", ui.OK, "as it should be"),
		run("one, not the router", R{Servers: []probe.DHCPServer{one}}, "192.168.1.254", ui.OK, "Pi-hole"),
		run("rogue", R{Servers: []probe.DHCPServer{one, rogue}}, "192.168.1.1", ui.Bad, "2 DHCP servers"),
		run("none", R{Servers: []probe.DHCPServer{}}, "192.168.1.1", ui.Warn, "No DHCP server"),
		run("no rights", R{Unavailable: "needs administrator rights"}, "", ui.Skip, "administrator"),
	})
}

func TestDHCPVerdictWifiExtender(t *testing.T) {
	// A real TP-Link extender in repeater mode: it answers the discover itself
	// but hands out the main router as gateway.
	r := probe.DHCPResult{Servers: []probe.DHCPServer{{ServerID: "192.168.0.250", Offered: "192.168.0.200", Router: "192.168.0.1"}}}
	checkCases(t, []vcase{
		vc("extender", r, "192.168.0.1", true, ui.OK, "Wi-Fi extender"),
		vc("not the access point", r, "192.168.0.1", false, ui.OK, "Pi-hole"),
		vc("access point, other gateway", r, "192.168.0.254", true, ui.OK, "Pi-hole"),
	})
}

func vc(name string, r probe.DHCPResult, gw string, viaAP bool, want ui.Status, has string) vcase {
	st, msg := dhcpVerdict(r, gw, viaAP)
	return vcase{name, st, msg, want, has}
}

func TestSameDevice(t *testing.T) {
	for _, c := range []struct {
		mac, bssid string
		want       bool
	}{
		{"aa:bb:cc:11:22:33", "aa:bb:cc:11:22:33", true},
		{"aa:bb:cc:11:22:33", "AA:BB:CC:11:22:35", true},
		{"aa:bb:cc:11:22:33", "aa:bb:cc:11:23:33", false},
		{"", "aa:bb:cc:11:22:33", false},
	} {
		if got := sameDevice(c.mac, c.bssid); got != c.want {
			t.Errorf("sameDevice(%q, %q) = %v", c.mac, c.bssid, got)
		}
	}
}

func TestEveryCommandIsReachable(t *testing.T) {
	for _, n := range append(append([]string{}, menuOrder...), extras...) {
		if find(n) == nil {
			t.Errorf("menu entry %q has no command", n)
		}
	}
	listed := map[string]bool{}
	for _, n := range append(append(append([]string{}, menuOrder...), extras...), setup...) {
		listed[n] = true
	}
	for _, t := range advancedTools {
		listed[t.cmd] = true // Advanced mode lists every planned tool
	}
	for _, c := range commands {
		if !listed[c.name] {
			t.Errorf("command %q isn't in the menu (or setup)", c.name)
		}
	}
	for _, n := range setup {
		if find(n) == nil {
			t.Errorf("setup command %q doesn't exist", n)
		}
	}
}

func TestAdvancedMenuLightsUpBuiltTools(t *testing.T) {
	items := advancedItems()
	if len(items) != len(advancedTools) {
		t.Fatalf("one menu item per planned tool")
	}
	for i, it := range items {
		if built := find(advancedTools[i].cmd) != nil; it.Ready != built {
			t.Errorf("%s: ready=%v but command exists=%v", it.Name, it.Ready, built)
		}
		if it.About == "" {
			t.Errorf("%s has no description", it.Name)
		}
	}
}

func TestUPnPVerdict(t *testing.T) {
	xbox := probe.PortMapping{Protocol: "UDP", ExternalPort: 3074, Client: "192.168.0.38", InternalPort: 3074, Enabled: true}
	plex := probe.PortMapping{Protocol: "TCP", ExternalPort: 32400, Client: "192.168.0.202", InternalPort: 32400, Enabled: true}
	run := func(name string, ms []probe.PortMapping, err error, want ui.Status, has string) vcase {
		st, msg := upnpVerdict(ms, err)
		return vcase{name, st, msg, want, has}
	}
	checkCases(t, []vcase{
		run("upnp off", nil, probe.ErrNoUPnP, ui.OK, "safer setting"),
		run("none open", []probe.PortMapping{}, nil, ui.OK, "no device has opened"),
		run("one", []probe.PortMapping{xbox}, nil, ui.OK, "1 port is open to the internet through UPnP, to 192.168.0.38"),
		run("two devices", []probe.PortMapping{xbox, plex, xbox}, nil, ui.OK, "3 ports are open to the internet through UPnP, to 2 devices"),
		run("broke midway", []probe.PortMapping{xbox}, errors.New("timeout"), ui.Warn, "incomplete"),
		run("broke at once", nil, errors.New("timeout"), ui.Warn, "Couldn't read"),
	})
}

func TestMappingNote(t *testing.T) {
	for _, c := range []struct {
		m    probe.PortMapping
		want string
	}{
		{probe.PortMapping{Description: "Xbox", Enabled: true}, "Xbox · permanent"},
		{probe.PortMapping{Description: "Plex", Enabled: true, LeaseSeconds: 7200}, "Plex · 2 h left"},
		{probe.PortMapping{Enabled: true, LeaseSeconds: 90}, "2 min left"},
		{probe.PortMapping{Description: "old", LeaseSeconds: 20, RemoteHost: "203.0.113.9"}, "old · 1 min left · only from 203.0.113.9 · disabled"},
	} {
		if got := mappingNote(c.m); got != c.want {
			t.Errorf("mappingNote(%+v) = %q, want %q", c.m, got, c.want)
		}
	}
}

func TestNATType(t *testing.T) {
	m := func(b, public string) probe.NATMapping { return probe.NATMapping{Behaviour: b, Public: public} }
	pub := net.ParseIP("198.51.100.41")
	cases := []struct {
		name  string
		m     probe.NATMapping
		wan   net.IP
		label string
		st    ui.Status
		has   string
	}{
		{"cone + upnp + public router", m("endpoint-independent", "198.51.100.41"), pub, "Open", ui.OK, "games can open the ports they need"},
		{"cone, no upnp", m("endpoint-independent", "198.51.100.41"), nil, "Moderate", ui.Warn, "doesn't offer UPnP"},
		{"cone behind cgnat", m("endpoint-independent", "198.51.100.41"), net.ParseIP("100.72.5.9"), "Moderate", ui.Warn, "(100.72.5.9) isn't your public one (198.51.100.41)"},
		{"symmetric", m("address-dependent", "198.51.100.41"), pub, "Strict", ui.Warn, "symmetric NAT"},
		{"udp blocked", m("udp-blocked", ""), nil, "Strict", ui.Warn, "UDP looks blocked"},
		{"no nat", m("none", "198.51.100.41"), nil, "Open", ui.OK, "no NAT in between"},
		{"unknown", m("unknown", "198.51.100.41"), nil, "unknown", ui.Skip, "Only one STUN server answered"},
	}
	for _, c := range cases {
		label, st, msg := natType(c.m, c.wan)
		if label != c.label || st != c.st || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got %s %v %q", c.name, label, st, msg)
		}
	}
}
