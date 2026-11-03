package uptime

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := map[string]Target{
		"https://example.com/health name=Shop_API expect=204 timeout=5s": {ID: "https://example.com/health", Name: "Shop API", Kind: HTTP, Addr: "https://example.com/health", Expect: "204", Timeout: 5 * time.Second},
		"example.com":                      {ID: "https://example.com", Name: "example.com", Kind: HTTP, Addr: "https://example.com", Timeout: 10 * time.Second},
		"tcp://db.internal:5432":           {ID: "tcp://db.internal:5432", Name: "db.internal:5432", Kind: TCP, Addr: "db.internal:5432", Timeout: 10 * time.Second},
		"10.0.0.5:22":                      {ID: "10.0.0.5:22", Name: "10.0.0.5:22", Kind: TCP, Addr: "10.0.0.5:22", Timeout: 10 * time.Second},
		"ping://192.168.0.1":               {ID: "ping://192.168.0.1", Name: "ping 192.168.0.1", Kind: Ping, Addr: "192.168.0.1", Timeout: 10 * time.Second},
		"dns://example.com expect=1.2.3.4": {ID: "dns://example.com", Name: "dns example.com", Kind: DNS, Addr: "example.com", Expect: "1.2.3.4", Timeout: 10 * time.Second},
	}
	for in, want := range cases {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("%q:\n got %+v %v\nwant %+v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "ftp://x", "tcp://nohost", "https://x.com expect=abc", "https://x.com timeout=2h", "https://x.com color=red", "https://x.com junk"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func cert(days int) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{NotAfter: fixed.Add(time.Duration(days)*24*time.Hour + time.Hour)}}}
}

var fixed = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func TestCheck(t *testing.T) {
	oldH, oldT, oldP, oldL, oldN := httpDo, dialTCP, ping, lookupHost, now
	defer func() { httpDo, dialTCP, ping, lookupHost, now = oldH, oldT, oldP, oldL, oldN }()
	now = func() time.Time { return fixed }
	httpDo = func(_ context.Context, t Target) (int, *tls.ConnectionState, error) {
		switch t.Addr {
		case "https://ok.test":
			return 200, cert(40), nil
		case "https://err.test":
			return 503, cert(40), nil
		case "https://moved.test":
			return 301, nil, nil
		}
		return 0, nil, errors.New("dial tcp: lookup nope.test: no such host")
	}
	dialTCP = func(_ context.Context, addr string, _ time.Duration) error {
		if addr == "10.0.0.1:22" {
			return nil
		}
		return errors.New("connect: connection refused")
	}
	ping = func(_ context.Context, host string, _ time.Duration) (float64, error) {
		if host == "10.0.0.1" {
			return 3.5, nil
		}
		return 0, errors.New("no answer")
	}
	lookupHost = func(_ context.Context, name string) ([]string, error) {
		return []string{"5.6.7.8", "1.2.3.4"}, nil
	}
	tg := func(s string) Target { x, _ := ParseTarget(s); return x }
	cases := []struct {
		target string
		ok     bool
		detail string
		cert   int
	}{
		{"https://ok.test", true, "200", 40},
		{"https://err.test", false, "503", 40},
		{"https://err.test expect=503", true, "503", 40},
		{"https://moved.test", true, "301", 0},
		{"https://nope.test", false, "name doesn't resolve", 0},
		{"tcp://10.0.0.1:22", true, "", 0},
		{"tcp://10.0.0.2:22", false, "connection refused", 0},
		{"ping://10.0.0.1", true, "", 0},
		{"ping://10.0.0.2", false, "no answer", 0},
		{"dns://x.test", true, "5.6.7.8,1.2.3.4", 0},
		{"dns://x.test expect=1.2.3.4", true, "1.2.3.4,5.6.7.8", 0},
		{"dns://x.test expect=9.9.9.9", false, "resolves to 1.2.3.4,5.6.7.8, not 9.9.9.9", 0},
	}
	for _, c := range cases {
		s := Check(context.Background(), tg(c.target))
		if s.OK != c.ok || s.Detail != c.detail || s.CertDays != c.cert || s.ID != tg(c.target).ID {
			t.Errorf("%s: %+v", c.target, s)
		}
	}
}

func TestMonitorEvents(t *testing.T) {
	tg, _ := ParseTarget("https://shop.test name=Shop")
	m := NewMonitor([]Target{tg}, 3, 14)
	at := fixed
	add := func(ok bool, certDays int) []Event {
		at = at.Add(30 * time.Second)
		s := Sample{Time: at, ID: tg.ID, OK: ok, Ms: 50, Detail: map[bool]string{true: "200", false: "503"}[ok], CertDays: certDays}
		return m.Add(s)
	}
	if e := add(true, 40); len(e) != 0 {
		t.Errorf("up from the start: %v", e)
	}
	add(false, 40)
	if e := add(false, 40); len(e) != 0 {
		t.Errorf("two failures aren't down yet: %v", e)
	}
	e := add(false, 40)
	if len(e) != 1 || e[0].Kind != "down" || e[0].Text != "Shop is down: 503" {
		t.Fatalf("down: %v", e)
	}
	if e := add(false, 40); len(e) != 0 {
		t.Errorf("down once, not again: %v", e)
	}
	e = add(true, 40)
	if len(e) != 1 || e[0].Kind != "up" || e[0].DownFor != time.Minute || e[0].Text != "Shop is back up after 1m0s" {
		t.Fatalf("up: %+v", e)
	}
	if e := add(true, 10); len(e) != 1 || e[0].Kind != "cert" || !strings.Contains(e[0].Text, "expires in 10 days") {
		t.Errorf("cert: %v", e)
	}
	if e := add(true, 9); len(e) != 0 {
		t.Errorf("cert warned once: %v", e)
	}
	st := m.Snapshot()[0]
	if st.Checks != 8 || st.Good != 4 || st.Uptime() != 50 || len(st.Series) != 8 || st.Series[1] != -1 || st.Down {
		t.Errorf("state: %+v", st)
	}
	if e := m.Add(Sample{ID: "unknown"}); e != nil {
		t.Error("unknown target")
	}
}

func TestLogAndSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uptime.jsonl")
	l, err := OpenLog(path)
	if err != nil {
		t.Fatal(err)
	}
	at := fixed
	write := func(id string, ok bool) {
		at = at.Add(time.Minute)
		l.Append(Sample{Time: at, ID: id, OK: ok, Ms: 100, Detail: map[bool]string{true: "200", false: "refused"}[ok], CertDays: 30})
	}
	// a: up, 3 down (an outage), up, 1 down (a blip), up, then 3 down to the end.
	for _, ok := range []bool{true, false, false, false, true, false, true, false, false, false} {
		write("a", ok)
	}
	write("b", true)
	l.Close()
	os.WriteFile(path+".1", []byte(`{"t":"2026-10-01T00:00:00Z","id":"a","ok":true,"ms":10}`+"\nnot json\n"), 0o644)

	all, err := ReadLog(path, time.Time{})
	if err != nil || len(all) != 12 || all[0].Ms != 10 {
		t.Fatalf("%d samples, %v", len(all), err)
	}
	recent, _ := ReadLog(path, fixed)
	sums := Summarize(recent, 3)
	a := sums["a"]
	if a.Checks != 10 || a.Good != 3 || len(a.Outages) != 2 || !a.Outages[0].Ended || a.Outages[1].Ended || a.Outages[0].Length != 3*time.Minute || a.AvgMs != 100 || a.CertDays != 30 {
		t.Errorf("a: %+v", a)
	}
	if sums["b"].Uptime != 100 || len(sums["b"].Outages) != 0 {
		t.Errorf("b: %+v", sums["b"])
	}
	if _, err := ReadLog(filepath.Join(t.TempDir(), "none.jsonl"), time.Time{}); err == nil {
		t.Error("no log")
	}
}

func TestRunChecksEveryTarget(t *testing.T) {
	oldT := dialTCP
	defer func() { dialTCP = oldT }()
	dialTCP = func(context.Context, string, time.Duration) error { return nil }
	var ts []Target
	for _, s := range []string{"tcp://a:1", "tcp://b:1", "tcp://c:1"} {
		x, _ := ParseTarget(s)
		ts = append(ts, x)
	}
	ctx, cancel := context.WithCancel(context.Background())
	got := make(chan Sample, 10)
	go Run(ctx, ts, time.Hour, func(s Sample) { got <- s })
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		select {
		case s := <-got:
			seen[s.ID] = s.OK
		case <-time.After(2 * time.Second):
			t.Fatal("not every target checked")
		}
	}
	cancel()
	if len(seen) != 3 {
		t.Errorf("%v", seen)
	}
}
