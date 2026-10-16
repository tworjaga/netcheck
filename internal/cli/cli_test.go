package cli

import (
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

func res(label, addr string, answered int, median float64, nx bool) probe.DNSResult {
	return probe.DNSResult{Label: label, Addr: addr, Lookups: 3, Answered: answered, MedianMs: median, RewritesNX: nx}
}

func TestDNSVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   []probe.DNSResult
		want ui.Status
		has  string
	}{
		{"healthy", []probe.DNSResult{res("System", "192.168.1.1", 3, 12, false), res("Cloudflare", "1.1.1.1", 3, 11, false)}, ui.OK, "healthy"},
		{"slow", []probe.DNSResult{res("System", "192.168.1.1", 3, 180, false), res("Cloudflare", "1.1.1.1", 3, 11, false)}, ui.Warn, "slow"},
		{"slow but close to public is fine", []probe.DNSResult{res("System", "192.168.1.1", 3, 90, false), res("Cloudflare", "1.1.1.1", 3, 70, false)}, ui.OK, "healthy"},
		{"nxdomain rewrite", []probe.DNSResult{res("System", "10.0.0.1", 3, 12, true), res("Cloudflare", "1.1.1.1", 3, 11, false)}, ui.Warn, "redirects"},
		{"system down, public up", []probe.DNSResult{res("System", "10.0.0.1", 0, 0, false), res("Cloudflare", "1.1.1.1", 3, 11, false)}, ui.Bad, "Cloudflare"},
		{"all down", []probe.DNSResult{res("System", "10.0.0.1", 0, 0, false), res("Cloudflare", "1.1.1.1", 0, 0, false)}, ui.Bad, "No DNS server"},
		{"dropped lookups", []probe.DNSResult{res("System", "10.0.0.1", 2, 12, false), res("Cloudflare", "1.1.1.1", 3, 11, false)}, ui.Warn, "dropped 1 of 3"},
		// A real slow network (school Wi-Fi): every resolver about 1.2 s.
		{"everything slow is the network", []probe.DNSResult{res("System", "", 3, 1254, false), res("Cloudflare", "1.1.1.1", 3, 1251, false), res("Quad9", "9.9.9.9", 3, 1252, false)}, ui.Warn, "it's the network that's slow, not your DNS"},
		{"fast public, slow everywhere else is still yours", []probe.DNSResult{res("System", "", 3, 400, false), res("Cloudflare", "1.1.1.1", 3, 20, false)}, ui.Warn, "DNS is slow (400 ms)"},
	}
	for _, c := range cases {
		st, msg, _ := dnsVerdict(c.in)
		if st != c.want || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got (%v, %q), want (%v, ...%q...)", c.name, st, msg, c.want, c.has)
		}
	}
}

func TestPingStatus(t *testing.T) {
	ok := probe.PingResult{Received: 10, AvgMs: 5}
	if pingStatus(ok, 25, ui.Skip) != ui.OK {
		t.Error("healthy ping should be OK")
	}
	lossy := probe.PingResult{Received: 8, LossPct: 20, AvgMs: 5}
	if pingStatus(lossy, 25, ui.Skip) != ui.Warn {
		t.Error("lossy ping should warn")
	}
	if pingStatus(probe.PingResult{}, 25, ui.Skip) != ui.Skip {
		t.Error("no reply should use the supplied status")
	}
}

func TestSpeedVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   probe.SpeedResult
		want ui.Status
		has  string
	}{
		{"good", probe.SpeedResult{DownMbps: 300, UpMbps: 40, Grade: "A", BloatMs: 8}, ui.OK, "good"},
		{"bloat F", probe.SpeedResult{DownMbps: 300, UpMbps: 40, Grade: "F", BloatMs: 400}, ui.Warn, "smart queue"},
		{"slow down", probe.SpeedResult{DownMbps: 3, UpMbps: 1, Grade: "A"}, ui.Warn, "Download speed is low"},
		{"slow up", probe.SpeedResult{DownMbps: 100, UpMbps: 0.5, Grade: "A"}, ui.Warn, "Upload speed is very low"},
		{"offline", probe.SpeedResult{Error: "offline"}, ui.Skip, "couldn't run"},
	}
	for _, c := range cases {
		st, msg := speedVerdict(c.in)
		if st != c.want || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got (%v, %q)", c.name, st, msg)
		}
	}
}

func TestWifiVerdict(t *testing.T) {
	good := probe.WifiInfo{Available: true, Connected: true, SignalDBm: -55, Band: "5 GHz", Channel: 36}
	weak := probe.WifiInfo{Available: true, Connected: true, SignalDBm: -80}
	crowded := probe.WifiInfo{Available: true, Connected: true, SignalDBm: -55, Channel: 6, Crowding: "crowded", Sharing: 7, BestChan: 11}
	cases := []struct {
		name string
		in   probe.WifiInfo
		want ui.Status
		has  string
	}{
		{"healthy", good, ui.OK, "healthy"},
		{"weak", weak, ui.Warn, "Move closer"},
		{"crowded", crowded, ui.Warn, "channel 11"},
		{"no adapter", probe.WifiInfo{}, ui.Skip, "cable"},
		{"not connected", probe.WifiInfo{Available: true}, ui.Skip, "isn't connected"},
	}
	for _, c := range cases {
		st, msg, _ := wifiVerdict(c.in)
		if st != c.want || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got (%v, %q)", c.name, st, msg)
		}
	}
}

func TestDeviceLine(t *testing.T) {
	line := deviceLine(probe.Device{IP: "192.168.1.1", Name: "fritz.box", Kind: "router", Vendor: "AVM Fritz!Box"})
	for _, want := range []string{"192.168.1.1", "fritz.box", "router", "AVM Fritz!Box"} {
		if !strings.Contains(line, want) {
			t.Errorf("%q missing from %q", want, line)
		}
	}
	a := deviceLine(probe.Device{IP: "192.168.1.9"})
	b := deviceLine(probe.Device{IP: "192.168.100.200", Name: "x", RandomMAC: true})
	if strings.Index(a, "–") != strings.Index(b, "x") || !strings.Contains(b, "private address") {
		t.Errorf("columns misaligned or private MAC not labelled:\n%q\n%q", a, b)
	}
}

func hop(ttl int, ip string, sent int, loss, avg float64) probe.Hop {
	return probe.Hop{TTL: ttl, IP: ip, Sent: sent, Received: sent, LossPct: loss, AvgMs: avg}
}

func TestRouteVerdict(t *testing.T) {
	clean := probe.RouteResult{Target: "1.1.1.1", Addr: "1.1.1.1", Reached: true, Hops: []probe.Hop{hop(1, "192.168.1.1", 10, 0, 2), hop(2, "84.1.1.1", 10, 0, 9), hop(3, "1.1.1.1", 10, 0, 12)}}
	rateLimited := clean
	rateLimited.Hops = []probe.Hop{hop(1, "192.168.1.1", 10, 0, 2), hop(2, "84.1.1.1", 10, 60, 9), hop(3, "1.1.1.1", 10, 0, 12)}
	realLoss := clean
	realLoss.Hops = []probe.Hop{hop(1, "192.168.1.1", 10, 0, 2), hop(2, "84.1.1.1", 10, 30, 9), hop(3, "1.1.1.1", 10, 30, 12)}
	jump := clean
	jump.Hops = []probe.Hop{hop(1, "192.168.1.1", 10, 0, 2), hop(2, "84.1.1.1", 10, 0, 9), hop(3, "1.1.1.1", 10, 0, 190)}
	faded := probe.RouteResult{Target: "10.9.9.9", Hops: []probe.Hop{hop(1, "192.168.1.1", 10, 0, 2)}}
	cases := []struct {
		name string
		in   probe.RouteResult
		want ui.Status
		has  string
	}{
		{"clean", clean, ui.OK, "looks clean"},
		{"rate limited middle hop is not a problem", rateLimited, ui.OK, "looks clean"},
		{"loss that reaches the end", realLoss, ui.Warn, "starts at hop 2"},
		{"latency jump", jump, ui.Warn, "jumps by 181 ms at hop 3"},
		{"fades out", faded, ui.Skip, "fades out"},
		{"error", probe.RouteResult{Error: "x"}, ui.Skip, "Couldn't trace"},
	}
	for _, c := range cases {
		st, msg := routeVerdict(c.in)
		if st != c.want || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got (%v, %q)", c.name, st, msg)
		}
	}
}

func TestPortsVerdict(t *testing.T) {
	https := []hostPorts{{IP: "192.168.1.1", Open: []probe.PortInfo{{Port: 80, Service: "http"}, {Port: 443, Service: "https"}}}}
	telnet := []hostPorts{{IP: "192.168.1.50", Open: []probe.PortInfo{{Port: 23, Service: "telnet"}}}}
	if st, _ := portsVerdict(https); st != ui.OK {
		t.Error("web ports on a router are normal")
	}
	if st, msg := portsVerdict(telnet); st != ui.Warn || !strings.Contains(msg, "192.168.1.50") {
		t.Errorf("telnet should warn and name the device, got (%v, %q)", st, msg)
	}
}

func TestExternalVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   probe.ExternalResult
		want ui.Status
		has  string
	}{
		{"open game port", probe.ExternalResult{Port: 25565, IP: "1.2.3.4", Open: true}, ui.OK, "reachable"},
		{"exposed rdp", probe.ExternalResult{Port: 3389, IP: "1.2.3.4", Open: true}, ui.Warn, "isn't meant to be exposed"},
		{"closed explains why", probe.ExternalResult{Port: 8080, IP: "1.2.3.4"}, ui.OK, "carrier-grade NAT"},
		{"helper down", probe.ExternalResult{Port: 80, Error: "couldn't reach the helper"}, ui.Skip, "Couldn't check"},
	}
	for _, c := range cases {
		st, msg := externalVerdict(c.in)
		if st != c.want || !strings.Contains(msg, c.has) {
			t.Errorf("%s: got (%v, %q)", c.name, st, msg)
		}
	}
}

func TestPortsLineMarksLegacy(t *testing.T) {
	line := portsLine(hostPorts{IP: "192.168.1.50", Open: []probe.PortInfo{{Port: 23, Service: "telnet"}, {Port: 80, Service: "http"}}})
	if !strings.Contains(line, "!") || !strings.Contains(line, "23 telnet · 80 http") {
		t.Errorf("got %q", line)
	}
}

func TestSQMAdvice(t *testing.T) {
	// The real line this was written on: 12.5 / 5.65 Mbps, grade F.
	got := sqmAdvice(probe.SpeedResult{DownMbps: 12.46, UpMbps: 5.65, Grade: "F", BloatMs: 373})
	if got == nil || got.DownMbps != 11 || got.UpMbps != 5 {
		t.Fatalf("got %+v", got)
	}
	if line := got.line(); !strings.Contains(line, "11000 kbit/s") || !strings.Contains(line, "5000 kbit/s") {
		t.Errorf("line: %s", line)
	}
	if got := sqmAdvice(probe.SpeedResult{DownMbps: 312, UpMbps: 41, Grade: "D"}); got == nil || got.DownMbps != 280 || got.UpMbps != 36 {
		t.Errorf("fast line: %+v", got)
	}
	for _, r := range []probe.SpeedResult{
		{DownMbps: 300, UpMbps: 40, Grade: "A"}, // no bloat, nothing to fix
		{DownMbps: 300, UpMbps: 40, Grade: "B"}, // mild
		{DownMbps: 300, Grade: "F"},             // upload unknown
		{Error: "unreachable", Grade: "F"},      // no test
	} {
		if got := sqmAdvice(r); got != nil {
			t.Errorf("%+v: want no advice, got %+v", r, got)
		}
	}
}
