package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/rdap"
	"github.com/tworjaga/netcheck/internal/tracex"
	"github.com/tworjaga/netcheck/internal/ui"
)

func route(reached bool, state string, last []float64) tracex.Result {
	return tracex.Result{Target: "example.com", Addr: "203.0.113.9", Proto: "tcp", Port: 443, Reached: reached, PortState: state, Hops: []tracex.Hop{
		{TTL: 1, IP: "192.168.0.1", Owner: "private network", RTTs: []float64{1, 1, 1}},
		{TTL: 2, IP: "198.51.100.1", ASN: 64500, Owner: "Transit Ltd", RTTs: []float64{10, 11, 12}},
		{TTL: 3, IP: "203.0.113.9", ASN: 64501, Owner: "Example Hosting", RTTs: last, Reached: reached},
	}}
}

func TestTraceRouteVerdict(t *testing.T) {
	st, msg, notes := routeVerdictAdv(route(true, "open", []float64{80, 81, 82}))
	if st != ui.OK || msg != "Reached example.com in 3 hops; port 443 is open (81 ms)." {
		t.Errorf("%v %q", st, msg)
	}
	all := strings.Join(notes, " ")
	if !strings.Contains(all, "private network") || !strings.Contains(all, "from hop 2 to 3 (+70 ms), at Example Hosting.") {
		t.Errorf("notes: %v", notes)
	}
	if st, msg, _ := routeVerdictAdv(route(true, "closed", []float64{80, 80, 80})); st != ui.Warn || !strings.Contains(msg, "port 443 is closed") {
		t.Errorf("closed: %v %q", st, msg)
	}
	if st, _, notes := routeVerdictAdv(route(true, "open", []float64{80, -1, 80})); st != ui.Warn || !strings.Contains(notes[0], "1 of 3 probes") {
		t.Errorf("loss: %v %v", st, notes)
	}
	r := route(false, "", []float64{-1, -1, -1})
	r.Hops[2].IP = ""
	if st, msg, notes := routeVerdictAdv(r); st != ui.Warn || !strings.Contains(msg, "hop 2 (198.51.100.1") || !strings.Contains(strings.Join(notes, " "), "firewall") {
		t.Errorf("not reached: %v %q %v", st, msg, notes)
	}
	r.Proto, r.Port = "udp", 53
	if _, _, notes := routeVerdictAdv(r); !strings.Contains(strings.Join(notes, " "), "service ignores a probe") {
		t.Errorf("udp to a service port: %v", notes)
	}
	if st, msg, _ := routeVerdictAdv(tracex.Result{Error: "TCP traces need root"}); st != ui.Bad || !strings.Contains(msg, "need root") {
		t.Errorf("error: %q", msg)
	}
	tb := routeTable(route(true, "open", []float64{80, 81, 82}), 78)
	for _, l := range tb.Lines(78) {
		if ui.VisWidth(l) > 78 {
			t.Errorf("too wide: %q", l)
		}
	}
}

func TestWhoisVerdict(t *testing.T) {
	soon := time.Now().Add(10 * 24 * time.Hour)
	later := time.Now().Add(400 * 24 * time.Hour)
	reg := time.Date(2001, 2, 3, 0, 0, 0, 0, time.UTC)
	d := whoisResult{Info: rdap.Info{Query: "example.com", Kind: "domain", Found: true, Name: "example.com", Registrar: "Reg Inc.",
		Registered: &reg, Expires: &later, Protocol: "rdap", Status: []string{"active"}}}
	st, msg, notes := whoisVerdict(d)
	if st != ui.OK || !strings.HasPrefix(msg, "example.com is registered with Reg Inc. since 2001-02-03; it runs until") || !strings.Contains(strings.Join(notes, " "), "Transfer lock is off") {
		t.Errorf("%v %q %v", st, msg, notes)
	}
	d.Expires, d.Status = &soon, []string{"client transfer prohibited"}
	if st, msg, notes := whoisVerdict(d); st != ui.Warn || !strings.Contains(msg, "; it expires in ") || strings.Contains(strings.Join(notes, " "), "Transfer lock") {
		t.Errorf("expiring: %v %q %v", st, msg, notes)
	}
	d.Status = []string{"redemption period"}
	if st, _, _ := whoisVerdict(d); st != ui.Bad {
		t.Error("redemption period is bad")
	}
	if v := whoisValues(d); v["expires"] > 10*24*3600*1000 || v["expires"] < 9*24*3600*1000 {
		t.Errorf("expires in ms: %v", v)
	}
	if st, msg, _ := whoisVerdict(whoisResult{Info: rdap.Info{Query: "free.com", Kind: "domain", Source: "https://rdap.verisign.com/com/v1/domain/free.com"}}); st != ui.Skip || msg != "free.com isn't registered, according to rdap.verisign.com." {
		t.Errorf("free: %q", msg)
	}
	ip := whoisResult{Info: rdap.Info{Query: "1.1.1.1", Kind: "ip", Found: true, CIDR: "1.1.1.0/24", Name: "APNIC-LABS", Abuse: "x@y"},
		Origin: &tracex.Owner{ASN: 13335, Name: "CLOUDFLARENET - Cloudflare, Inc., US"}}
	if _, msg, _ := whoisVerdict(ip); msg != "1.1.1.1 is in 1.1.1.0/24 (APNIC-LABS); announced by AS13335 Cloudflare, Inc." {
		t.Errorf("ip: %q", msg)
	}
}
