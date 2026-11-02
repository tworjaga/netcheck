package cli

import (
	"strings"
	"testing"

	"github.com/tworjaga/netcheck/internal/probe"
	"github.com/tworjaga/netcheck/internal/ui"
)

func ping(avg, jitter, loss float64) *probe.PingResult {
	r := &probe.PingResult{Sent: 10, Received: 10, AvgMs: avg, JitterMs: jitter, LossPct: loss}
	if loss >= 100 {
		r.Received = 0
	}
	return r
}

func goodDNS() []probe.DNSResult {
	return []probe.DNSResult{res("System", "192.168.1.1", 3, 12, false), res("Cloudflare", "1.1.1.1", 3, 11, false)}
}

func wifi(dbm int, crowding string) *probe.WifiInfo {
	return &probe.WifiInfo{Available: true, Connected: true, SSID: "Home", SignalDBm: dbm, Channel: 6, Band: "2.4 GHz", Crowding: crowding, Sharing: 7, BestChan: 11}
}

// healthy is a good fibre connection on decent Wi-Fi.
func healthy() doctorData {
	d := doctorData{
		GatewayFound: true,
		Gateway:      ping(3, 1, 0),
		Internet:     ping(14, 2, 0),
		DNS:          goodDNS(),
		Wifi:         wifi(-55, "quiet"),
		IPv6:         &probe.IPv6Result{Reachable: true, V6Ms: 14, V4Ms: 14, DNSAAAA: true, Preferred: true},
		NAT:          &probe.NATInfo{Kind: "none"},
		Speed:        &probe.SpeedResult{DownMbps: 300, UpMbps: 40, Grade: "A", BloatMs: 8, IdleMs: 14},
	}
	d.Readiness = readiness(link{PingKnown: true, LatencyMs: 14, JitterMs: 2, LossKnown: true, DownMbps: 300, UpMbps: 40, LoadedMs: 22})
	return d
}

func TestDoctorFindingsLeadWithTheMostSerious(t *testing.T) {
	cases := []struct {
		name  string
		mod   func(d *doctorData)
		want  ui.Status
		lead  string
		count int // -1: don't check
	}{
		{"healthy", func(d *doctorData) {}, ui.OK, "healthy", 0},
		{"offline beats everything", func(d *doctorData) {
			d.Gateway, d.Internet = ping(0, 0, 100), ping(0, 0, 100)
			d.DNS, d.IPv6, d.NAT, d.Speed, d.Readiness = nil, nil, &probe.NATInfo{Kind: "cgnat"}, nil, nil
		}, ui.Bad, "Can't reach your router or the internet", -1},
		{"offline with weak wifi names the cause", func(d *doctorData) {
			d.Gateway, d.Internet, d.Wifi = ping(0, 0, 100), ping(0, 0, 100), wifi(-86, "")
			d.DNS, d.IPv6, d.Speed, d.Readiness = nil, nil, nil, nil
		}, ui.Bad, "very weak (-86 dBm)", -1},
		{"ISP down, router fine", func(d *doctorData) {
			d.Internet = ping(0, 0, 100)
			d.DNS, d.Speed, d.Readiness = nil, nil, nil
		}, ui.Bad, "router answers but the internet doesn't", -1},
		{"DNS dead beats CGNAT and bloat", func(d *doctorData) {
			d.DNS = []probe.DNSResult{res("System", "10.0.0.1", 0, 0, false), res("Cloudflare", "1.1.1.1", 3, 11, false)}
			d.NAT = &probe.NATInfo{Kind: "cgnat"}
			d.Speed.Grade, d.Speed.BloatMs = "F", 400
		}, ui.Bad, "DNS server isn't answering", -1},
		{"weak wifi and loss to router are one story", func(d *doctorData) {
			d.Wifi = wifi(-80, "quiet")
			d.Gateway = ping(9, 6, 20)
			d.Internet = ping(25, 8, 20)
		}, ui.Warn, "Weak Wi-Fi (-80 dBm) is losing packets: 20%", -1},
		{"loss past the router blames the line", func(d *doctorData) {
			d.Internet = ping(30, 5, 10)
		}, ui.Warn, "past your home network", -1},
		{"bufferbloat before CGNAT", func(d *doctorData) {
			d.Speed.Grade, d.Speed.BloatMs = "F", 400
			d.NAT = &probe.NATInfo{Kind: "cgnat"}
		}, ui.Warn, "stalls when it's busy", -1},
		{"crowded channel is minor but reported", func(d *doctorData) {
			d.Wifi = wifi(-55, "crowded")
		}, ui.Warn, "channel 6 is crowded", 1},
		{"cgnat alone", func(d *doctorData) {
			d.NAT = &probe.NATInfo{Kind: "cgnat"}
		}, ui.Warn, "carrier-grade NAT", 1},
		{"cgnat with working ipv6 says so", func(d *doctorData) {
			d.NAT = &probe.NATInfo{Kind: "cgnat"}
		}, ui.Warn, "IPv6 works here", 1},
		{"broken ipv6", func(d *doctorData) {
			d.IPv6 = &probe.IPv6Result{Address: "2001:db8::1", V4Ms: 14, DNSAAAA: true}
		}, ui.Warn, "IPv6 is set up", 1},
		{"ipv4-only is not a problem", func(d *doctorData) {
			d.IPv6 = &probe.IPv6Result{V4Ms: 14}
		}, ui.OK, "healthy", 0},
		{"satellite: readiness explains it", func(d *doctorData) {
			d.Internet = ping(600, 10, 0)
			d.Readiness = readiness(link{PingKnown: true, LatencyMs: 600, JitterMs: 10, LossKnown: true, DownMbps: 100, UpMbps: 10})
		}, ui.Warn, "High latency", 2},
		{"fast mode, no speed", func(d *doctorData) {
			d.Speed = nil
			d.Readiness = readiness(link{PingKnown: true, LatencyMs: 14, JitterMs: 2, LossKnown: true})
		}, ui.OK, "healthy", 0},
	}
	for _, c := range cases {
		d := healthy()
		c.mod(&d)
		fs := doctorFindings(d)
		st, head := lead(fs, "Your connection looks healthy.")
		if st != c.want || !strings.Contains(head, c.lead) {
			t.Errorf("%s: got (%v, %q)\n  all: %+v", c.name, st, head, fs)
		}
		if c.count >= 0 && len(fs) != c.count {
			t.Errorf("%s: want %d findings, got %d: %+v", c.name, c.count, len(fs), fs)
		}
	}
}

func TestDoctorRows(t *testing.T) {
	if r := wifiDoctorRow(probe.WifiInfo{}); !strings.Contains(r, "not in use") {
		t.Errorf("wired: %q", r)
	}
	if r := wifiDoctorRow(*wifi(-55, "quiet")); !strings.Contains(r, "-55 dBm") || !strings.Contains(r, "quiet channel") {
		t.Errorf("wifi: %q", r)
	}
	if r := ipv6DoctorRow(probe.IPv6Result{V4Ms: 10}); !strings.Contains(r, "IPv4 only") {
		t.Errorf("ipv6: %q", r)
	}
	if r := speedDoctorRow(probe.SpeedResult{DownMbps: 312.4, UpMbps: 41.2, Grade: "B", BloatMs: 42}); !strings.Contains(r, "312 / 41 Mbps") || !strings.Contains(r, "bufferbloat B") {
		t.Errorf("speed: %q", r)
	}
}
