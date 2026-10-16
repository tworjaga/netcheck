package cli

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/history"
	"github.com/tworjaga/netcheck/internal/probe"
)

func sampleReport() reportData {
	d := healthy()
	d.Gateway.Method, d.Internet.Method, d.Internet.Addr = "icmp", "icmp", "1.1.1.1"
	d.NAT = &probe.NATInfo{Kind: "cgnat", Detail: "Your ISP shares addresses | between customers."}
	d.Wifi.SSID, d.Wifi.BSSID = "Secret Home Net", "aa:bb:cc:dd:ee:ff"
	d.Wifi.Neighbors = []probe.WifiNet{{SSID: "Neighbour"}}
	st, head, fs := doctorVerdict(d)
	gen := time.Date(2026, 10, 13, 21, 4, 0, 0, time.FixedZone("CEST", 2*3600))
	ss := []history.Sample{}
	for i := 0; i < 40; i++ {
		v := 15.0
		if i >= 10 && i < 14 {
			v = -1
		}
		ss = append(ss, history.Sample{V: 1, T: gen.Add(-time.Hour + time.Duration(i)*5*time.Second), Net: history.Ms(v), GW: history.Ms(2)})
	}
	h := history.Analyze(ss, gen.Location())
	return reportData{
		Generated: gen, Version: "0.3.0", Platform: "windows/amd64",
		LocalIP: "192.168.1.23", Gateway: "192.168.1.1",
		Public:  probe.IPInfo{IP: "203.0.113.7", ASN: "AS64500", ISP: "HOMEISP"},
		Verdict: verdict{st.String(), head}, Findings: findingsJSON(fs),
		Checks: doctorReport{Gateway: d.Gateway, Internet: d.Internet, DNS: d.DNS, Readiness: d.Readiness,
			Wifi: d.Wifi, IPv6: d.IPv6, NAT: d.NAT, Speed: d.Speed},
		Route: &probe.RouteResult{Addr: "1.1.1.1", Hops: []probe.Hop{
			{TTL: 1, IP: "192.168.1.1", Sent: 5, Received: 5, AvgMs: 2, WorstMs: 3},
			{TTL: 2},
			{TTL: 3, IP: "1.1.1.1", Sent: 5, Received: 5, AvgMs: 14, WorstMs: 18},
		}},
		History: &h, HistoryDays: 7,
	}
}

func TestRenderMarkdown(t *testing.T) {
	md := renderMarkdown(sampleReport())
	for _, want := range []string{
		"# Network report",
		"Generated Tue 13 Oct 2026 21:04 CEST by netcheck 0.3.0 on windows/amd64.",
		"## Summary\n\n**",  // headline in bold
		"carrier-grade NAT", // the CGNAT finding
		"| Public IP | 203.0.113.7 |",
		"| ISP | HOMEISP AS64500 |",
		`addresses \| between`,                  // pipes escaped inside table cells
		"| Router 192.168.1.1 | 3.0 ms average", // measurements with numbers
		"ICMP ping",
		"300 Mbps down, 40.0 Mbps up; latency 14 ms idle (bufferbloat grade A)",
		"## Good for",
		"- **Video calls:** good. Steady, low latency.",
		"- From monitoring with netcheck watch: the internet dropped out once",
		"| 2 | (no reply) | | | |",
		"## History (last 7 days)",
		"Outages (2 or more lost probes in a row): 1, 20 s in total.",
		"| Router during the outage |",
		"answering normally",
		"## How this was measured",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, leak := range []string{"Secret Home Net", "aa:bb:cc", "Neighbour"} {
		if strings.Contains(md, leak) {
			t.Errorf("report must not contain %q", leak)
		}
	}
}

func TestRenderMarkdownMinimal(t *testing.T) {
	// Offline, fast, no history: still a valid report, no empty sections.
	d := doctorData{Gateway: ping(0, 0, 100), Internet: ping(0, 0, 100)}
	st, head, fs := doctorVerdict(d)
	md := renderMarkdown(reportData{Generated: time.Now(), Version: "x", Platform: "linux/amd64",
		Verdict: verdict{st.String(), head}, Findings: findingsJSON(fs),
		Checks: doctorReport{Gateway: d.Gateway, Internet: d.Internet}})
	if !strings.Contains(md, "Can't reach your router or the internet") {
		t.Fatalf("verdict missing:\n%s", md)
	}
	for _, absent := range []string{"## Route", "## History", "## Good for", "| Public IP"} {
		if strings.Contains(md, absent) {
			t.Errorf("%q shouldn't appear without data", absent)
		}
	}
}

func TestRedactWifiForJSON(t *testing.T) {
	w := redactWifi(&probe.WifiInfo{SSID: "Secret", BSSID: "aa:bb", SignalDBm: -60, Neighbors: []probe.WifiNet{{SSID: "N"}}})
	b, _ := json.Marshal(w)
	if strings.Contains(string(b), "Secret") || strings.Contains(string(b), "aa:bb") || strings.Contains(string(b), `"N"`) || !strings.Contains(string(b), "-60") {
		t.Fatalf("got %s", b)
	}
	if redactWifi(nil) != nil {
		t.Fatal("nil stays nil")
	}
}
