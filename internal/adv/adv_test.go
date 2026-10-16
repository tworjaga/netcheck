package adv

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := []struct {
		in           string
		host, scheme string
		port         int
		path         string
		bad          bool
	}{
		{in: "example.com", host: "example.com"},
		{in: "example.com:8443", host: "example.com", port: 8443},
		{in: "10.0.0.5:22", host: "10.0.0.5", port: 22},
		{in: "2001:db8::1", host: "2001:db8::1"},
		{in: "[2001:db8::1]:443", host: "2001:db8::1", port: 443},
		{in: "https://example.com/health", host: "example.com", scheme: "https", port: 443, path: "/health"},
		{in: "http://10.0.0.5:8080/", host: "10.0.0.5", scheme: "http", port: 8080, path: "/"},
		{in: "example.com:99999", bad: true},
		{in: "exa mple.com", bad: true},
		{in: "", bad: true},
	}
	for _, c := range cases {
		got, err := Parse(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%q: want an error, got %+v", c.in, got)
			}
			continue
		}
		if err != nil || got.Host != c.host || got.Port != c.port || got.Scheme != c.scheme || got.Path != c.path {
			t.Errorf("%q: got %+v, %v", c.in, got, err)
		}
	}
	tg, _ := Parse("example.com")
	if tg.Addr(443) != "example.com:443" {
		t.Errorf("Addr default: %s", tg.Addr(443))
	}
	if v6, _ := Parse("2001:db8::1"); v6.Addr(22) != "[2001:db8::1]:22" {
		t.Errorf("Addr v6: %s", v6.Addr(22))
	}
}

func TestExpand(t *testing.T) {
	ts, err := Expand("192.168.0.0/30")
	if err != nil || len(ts) != 2 || ts[0].Host != "192.168.0.1" || ts[1].Host != "192.168.0.2" {
		t.Fatalf("/30 has two usable hosts: %+v %v", ts, err)
	}
	ts, _ = Expand("10.0.0.0/24:22")
	if len(ts) != 254 || ts[0].Port != 22 || ts[253].Host != "10.0.0.254" {
		t.Fatalf("/24 with a port: %d targets, first %+v", len(ts), ts[0])
	}
	if ts, _ := Expand("10.0.0.7/32"); len(ts) != 1 || ts[0].Host != "10.0.0.7" {
		t.Errorf("/32: %+v", ts)
	}
	if _, err := Expand("10.0.0.0/16"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("a /16 is refused: %v", err)
	}
	if ts, _ := Expand("example.com:443"); len(ts) != 1 || ts[0].Port != 443 {
		t.Errorf("non-range passes through: %+v", ts)
	}
}

func TestTargetsFromFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hosts.txt")
	body := "# my servers\ndb.lan:5432\n\n  redis.lan:6379   # cache\n192.168.0.0/31\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, err := Targets([]string{"api.example.com:443"}, path)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for _, x := range ts {
		hosts = append(hosts, x.Addr(0))
	}
	want := "api.example.com:443 db.lan:5432 redis.lan:6379 192.168.0.0:0 192.168.0.1:0"
	if strings.Join(hosts, " ") != want {
		t.Errorf("got %s", strings.Join(hosts, " "))
	}
	os.WriteFile(path, []byte("ok.lan\nbad host here\n"), 0o600)
	if _, err := Targets(nil, path); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("errors name the line: %v", err)
	}
}

func TestParseRules(t *testing.T) {
	rules, err := ParseRules("14d, loss>1%,rtt>200ms , grade<B")
	if err != nil || len(rules) != 4 {
		t.Fatalf("%+v %v", rules, err)
	}
	day := 24 * 3600 * 1000.0
	if r := rules[0]; r.Metric != "" || r.Op != 0 || r.Value != 14*day {
		t.Errorf("bare value: %+v", r)
	}
	if r := rules[1]; r.Metric != "loss" || r.Op != '>' || r.Value != 1 {
		t.Errorf("percent: %+v", r)
	}
	if r := rules[2]; r.Metric != "rtt" || r.Value != 200 {
		t.Errorf("ms: %+v", r)
	}
	if r := rules[3]; r.Metric != "grade" || r.Op != '<' || r.Value != 4 {
		t.Errorf("grade: %+v", r)
	}
	for _, bad := range []string{"<5", "loss>lots", "14 days"} {
		if _, err := ParseRules(bad); err == nil {
			t.Errorf("%q should be rejected", bad)
		}
	}
}

func TestBrokenRules(t *testing.T) {
	day := 24 * 3600 * 1000.0
	rules, _ := ParseRules("14d,grade<B,loss>1%,lantency>5ms")
	got := Broken(rules, Default{Metric: "expiry", Op: '<'}, map[string]float64{"expiry": 9.5 * day, "grade": 3, "loss": 0.5})
	all := strings.Join(got, " | ")
	if len(got) != 3 || !strings.Contains(all, "14d: expiry is 9.5d") || !strings.Contains(all, "grade<B: grade is C") || !strings.Contains(all, `doesn't measure "lantency"`) {
		t.Errorf("got %s", all)
	}
	if ok := Broken(rules[:1], Default{"expiry", '<'}, map[string]float64{"expiry": 40 * day}); len(ok) != 0 {
		t.Errorf("40 days left passes 14d: %v", ok)
	}
	if ExitCode("ok", nil) != 0 || ExitCode("warn", nil) != 0 || ExitCode("bad", nil) != 1 || ExitCode("ok", got) != 1 {
		t.Error("ExitCode")
	}
}

func TestCheckScope(t *testing.T) {
	old := resolve
	resolve = func(_ context.Context, host string) ([]net.IP, error) {
		return map[string][]net.IP{
			"nas.lan":     {net.ParseIP("192.168.0.20")},
			"example.com": {net.ParseIP("93.184.216.34")},
		}[host], nil
	}
	defer func() { resolve = old }()
	ctx := context.Background()
	own, _ := Targets([]string{"192.168.0.0/30", "nas.lan:445", "127.0.0.1", "100.64.1.1", "fe80::1"}, "")
	if err := CheckScope(ctx, own, false); err != nil {
		t.Errorf("own networks need no flag: %v", err)
	}
	public, _ := Targets([]string{"nas.lan", "example.com", "8.8.8.8"}, "")
	err := CheckScope(ctx, public, false)
	if err == nil || !strings.Contains(err.Error(), "example.com, 8.8.8.8") || !strings.Contains(err.Error(), "--authorized") {
		t.Errorf("public targets need --authorized: %v", err)
	}
	if err := CheckScope(ctx, public, true); err != nil {
		t.Errorf("--authorized allows them: %v", err)
	}
}

func TestPacer(t *testing.T) {
	now := time.Unix(0, 0)
	var waits []time.Duration
	p := NewPacer(10)
	p.now = func() time.Time { return now }
	p.sleep = func(_ context.Context, d time.Duration) { waits = append(waits, d) }
	for i := 0; i < 3; i++ {
		p.Wait(context.Background())
	}
	if len(waits) != 3 || waits[0] != 0 || waits[1] != 100*time.Millisecond || waits[2] != 200*time.Millisecond {
		t.Errorf("10 a second are 100 ms apart: %v", waits)
	}
	if err := NewPacer(0).Wait(context.Background()); err != nil {
		t.Errorf("no limit: %v", err)
	}
}

func TestEnvelopeJSON(t *testing.T) {
	tg, _ := Parse("example.com:443")
	var buf bytes.Buffer
	e := Envelope{Tool: "cert", Version: "0.5.0", Time: time.Date(2026, 10, 14, 0, 0, 0, 0, time.UTC),
		Targets: []Target{tg}, Verdict: Finding{"warn", "expires in 9 days"}, Data: map[string]int{"days_left": 9}, FailedOn: []string{"14d: expiry is 9.0d"}}
	if err := e.Write(&buf); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"tool", "netcheck_version", "time", "targets", "verdict", "findings", "data", "failed_on"} {
		if _, ok := back[k]; !ok {
			t.Errorf("missing %q in %s", k, buf.String())
		}
	}
	if f, ok := back["findings"].([]any); !ok || len(f) != 0 {
		t.Errorf("findings is an empty list, not null: %v", back["findings"])
	}
}
