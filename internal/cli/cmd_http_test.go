package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/domain"
	"github.com/tworjaga/netcheck/internal/ui"
	"github.com/tworjaga/netcheck/internal/webx"
)

func webHop(status int, total, wait time.Duration) webx.Hop {
	return webx.Hop{Status: status, StatusText: "x", URL: "https://example.com/", Proto: "HTTP/2.0", TLSVersion: "TLS 1.3",
		Phases: webx.Phases{DNS: 5 * time.Millisecond, Connect: 10 * time.Millisecond, TLS: 20 * time.Millisecond, Wait: wait, Download: 5 * time.Millisecond, Total: total}}
}

func TestHTTPVerdict(t *testing.T) {
	r := webx.Result{Hops: []webx.Hop{webHop(200, 140*time.Millisecond, 100*time.Millisecond)}, Total: 140 * time.Millisecond}
	if st, msg, notes := httpVerdict(r); st != ui.OK || !strings.Contains(msg, "the server preparing the answer (100 ms)") || len(notes) != 0 {
		t.Errorf("%v %q %v", st, msg, notes)
	}
	r.Hops = append([]webx.Hop{webHop(301, 30*time.Millisecond, 5*time.Millisecond)}, r.Hops...)
	if _, msg, _ := httpVerdict(r); !strings.Contains(msg, "30 ms of it on 1 redirect") {
		t.Errorf("redirects: %q", msg)
	}
	slow := webx.Result{Hops: []webx.Hop{webHop(503, 2*time.Second, 1900*time.Millisecond)}, Total: 2 * time.Second}
	if st, _, notes := httpVerdict(slow); st != ui.Bad || !strings.Contains(strings.Join(notes, " "), "application or database") {
		t.Errorf("slow 503: %v %v", st, notes)
	}
	h1 := webHop(404, time.Second/10, time.Second/20)
	h1.Proto = "HTTP/1.1"
	if st, _, notes := httpVerdict(webx.Result{Hops: []webx.Hop{h1}}); st != ui.Warn || !strings.Contains(strings.Join(notes, " "), "HTTP/2") {
		t.Errorf("404 over HTTP/1.1: %v %v", st, notes)
	}
	if st, msg, _ := httpVerdict(webx.Result{Hops: []webx.Hop{{Error: "x"}}, Error: "connection refused"}); st != ui.Bad || msg != "The request failed: connection refused." {
		t.Errorf("error: %q", msg)
	}
}

func TestWaterfall(t *testing.T) {
	p := webHop(200, 140*time.Millisecond, 100*time.Millisecond).Phases
	lines := waterfall(p, 60)
	if len(lines) != 6 || !strings.Contains(lines[5], "140 ms") {
		t.Fatalf("%q", lines)
	}
	for _, l := range lines {
		if ui.VisWidth(l) > 60 {
			t.Errorf("too wide: %q", l)
		}
	}
	// The server bar starts where TLS ended: it's the widest, last but one.
	if strings.Index(lines[3], ui.Pick("█", "#")) <= strings.Index(lines[2], ui.Pick("█", "#")) {
		t.Errorf("bars don't follow each other:\n%s", strings.Join(lines, "\n"))
	}
}

func TestCertTarget(t *testing.T) {
	cases := map[string]struct {
		host string
		port int
	}{
		"example.com": {"example.com", 0}, "example.com:8443": {"example.com", 8443}, "[2001:db8::1]:993": {"2001:db8::1", 993},
		"https://example.com/x": {"example.com", 443}, "imaps://mail.example.com": {"mail.example.com", 993}, "2001:db8::1": {"2001:db8::1", 0},
	}
	for in, want := range cases {
		h, p, err := certTarget(in)
		if err != nil || h != want.host || p != want.port {
			t.Errorf("%s: %q %d %v", in, h, p, err)
		}
	}
	if _, _, err := certTarget("example.com:99999"); err == nil {
		t.Error("bad port")
	}
}

func TestCertVerdict(t *testing.T) {
	r := webx.CertReport{Host: "example.com", Port: 443, Chain: []webx.CertInfo{{Days: 60}},
		Checks: []domain.Check{{Status: domain.OK, Title: "Trusted"}}}
	if st, msg, _ := certVerdict(r); st != ui.OK || msg != "example.com's certificate is trusted and valid for 60 more days." {
		t.Errorf("%v %q", st, msg)
	}
	r.Port, r.Problem = 8443, "name"
	r.Checks = []domain.Check{{Status: domain.Bad, Title: "Wrong name: not valid for example.com", Fix: "x"}}
	if st, msg, _ := certVerdict(r); st != ui.Bad || msg != "Clients refuse example.com:8443's certificate: wrong name: not valid for example.com." {
		t.Errorf("%v %q", st, msg)
	}
	r.Problem = ""
	r.Checks = []domain.Check{{Status: domain.Warn, Title: "Accepts TLS 1.0"}}
	if st, msg, _ := certVerdict(r); st != ui.Warn || !strings.Contains(msg, "1 thing to look at") {
		t.Errorf("%v %q", st, msg)
	}
	if v := certValues(webx.CertReport{Chain: []webx.CertInfo{{Days: 10}}}); v["days"] != 10*24*3600*1000 {
		t.Errorf("days in ms: %v", v)
	}
}
