package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckArgs(t *testing.T) {
	ok := [][]string{{"dig", "example.com", "MX"}, {"http", "https://x.test", "-n", "3"}, {"uptime", "--once", "https://x.test"}, {"connect", "x.test:25", "-s", "QUIT"}, {"reach", "10.0.0.1:22", "deny"}}
	for _, a := range ok {
		if err := CheckArgs(a[0], a[1:]); err != nil {
			t.Errorf("%v: %v", a, err)
		}
	}
	bad := [][]string{{"perf", "--server"}, {"agent"}, {"wake", "aa:bb:cc:dd:ee:ff"}, {"lanaudit"}, {"dig", "-f", "/etc/passwd"}, {"http", "x", "--watch", "5s"},
		{"uptime", "https://x"}, {"uptime", "--once", "--notify", "x"}, {"connect", "x:25"}, {"domain", "-f=list.txt"}, {"port", "445"}, {"open", "8080"}}
	for _, a := range bad {
		if err := CheckArgs(a[0], a[1:]); err == nil {
			t.Errorf("%v should be refused", a)
		}
	}
}

func TestCheckListen(t *testing.T) {
	for _, a := range []string{"127.0.0.1:5299", "[::1]:5299", "localhost:5299"} {
		if err := CheckListen(a); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range []string{"0.0.0.0:5299", ":5299", "192.168.0.200:5299", "nonsense"} {
		if err := CheckListen(a); err == nil {
			t.Errorf("%s should be refused", a)
		}
	}
}

func testAgent(t *testing.T) (*Server, Remote, *[]string) {
	t.Helper()
	var ran []string
	s := &Server{Token: "secret-token", Version: "9.9", OS: "linux",
		Run: func(_ context.Context, tool string, args []string, asJSON bool) (string, int) {
			ran = append(ran, tool+" "+strings.Join(args, " "))
			if asJSON {
				return `{"tool":"` + tool + `"}`, 0
			}
			return "  netcheck  " + tool + "\n  all good\n", 0
		},
		DialBack: func(_ context.Context, addr string) bool { return addr == "203.0.113.7:8080" },
	}
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return s, Remote{Name: "vps", URL: srv.URL, Token: "secret-token"}, &ran
}

func TestServerAndClient(t *testing.T) {
	_, r, ran := testAgent(t)
	ctx := context.Background()
	h, err := r.Hello(ctx)
	if err != nil || h.Agent != "netcheck" || h.Version != "9.9" || h.OS != "linux" {
		t.Fatalf("hello: %+v %v", h, err)
	}
	res, err := r.Run(ctx, "dig", []string{"example.com"}, false)
	if err != nil || res.Exit != 0 || !strings.Contains(res.Output, "all good") || (*ran)[0] != "dig example.com" {
		t.Errorf("run: %+v %v %v", res, err, *ran)
	}
	if res, _ := r.Run(ctx, "http", []string{"x"}, true); res.Output != `{"tool":"http"}` {
		t.Errorf("json: %q", res.Output)
	}
	if _, err := r.Run(ctx, "dig", []string{"-f", "/etc/shadow"}, false); err == nil || !strings.Contains(err.Error(), "-f isn't allowed") {
		t.Errorf("denied flag: %v", err)
	}
	wrong := r
	wrong.Token = "guess"
	if _, err := wrong.Hello(ctx); err == nil || !strings.Contains(err.Error(), "wrong or missing token") {
		t.Errorf("wrong token: %v", err)
	}
	if len(*ran) != 2 {
		t.Errorf("refused requests must not run anything: %v", *ran)
	}
}

func TestPortCheckUsesTheTunnelsCallerIP(t *testing.T) {
	s, _, _ := testAgent(t)
	ask := func(remote, cf string) PortResult {
		req := httptest.NewRequest("GET", "/v1/port?port=8080", nil)
		req.RemoteAddr = remote
		req.Header.Set("Authorization", "Bearer secret-token")
		if cf != "" {
			req.Header.Set("CF-Connecting-IP", cf)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		var res PortResult
		decode(t, w.Body, &res)
		return res
	}
	// Through cloudflared: the request comes from 127.0.0.1, the caller is in the header.
	if r := ask("127.0.0.1:50000", "203.0.113.7"); !r.Open || r.IP != "203.0.113.7" {
		t.Errorf("through the tunnel: %+v", r)
	}
	// The header doesn't count from outside: nobody can point the agent at someone else.
	if r := ask("198.51.100.9:50000", "203.0.113.7"); r.IP != "198.51.100.9" || r.Open {
		t.Errorf("spoofed header: %+v", r)
	}
	if r := ask("127.0.0.1:50000", ""); r.Error == "" || r.Open {
		t.Errorf("a local caller can't be tested: %+v", r)
	}
}

func decode(t *testing.T, r io.Reader, v any) {
	t.Helper()
	b, _ := io.ReadAll(r)
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
}

func TestRateLimit(t *testing.T) {
	s := &Server{Token: "t", Run: func(context.Context, string, []string, bool) (string, int) { return "", 0 }}
	refused := 0
	for i := 0; i < 15; i++ {
		req := httptest.NewRequest("GET", "/v1/hello", nil)
		req.Header.Set("Authorization", "Bearer t")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			refused++
		}
	}
	if refused < 4 {
		t.Errorf("a burst of 15 should be slowed: %d refused", refused)
	}
}

func TestQuickTunnel(t *testing.T) {
	old := startCloudflared
	defer func() { startCloudflared = old }()
	startCloudflared = func(context.Context, string) (io.ReadCloser, func() error, error) {
		out := "2026-10-16T00:10:00Z INF Requesting new quick Tunnel on trycloudflare.com...\n" +
			"2026-10-16T00:10:02Z INF |  https://quiet-river-1234.trycloudflare.com  |\n"
		return io.NopCloser(strings.NewReader(out)), func() error { time.Sleep(50 * time.Millisecond); return nil }, nil
	}
	u, done, err := QuickTunnel(context.Background(), DefaultListen)
	if err != nil || u != "https://quiet-river-1234.trycloudflare.com" || done == nil {
		t.Errorf("%q %v", u, err)
	}
	startCloudflared = func(context.Context, string) (io.ReadCloser, func() error, error) {
		return io.NopCloser(strings.NewReader("ERR failed to connect\n")), func() error { return nil }, nil
	}
	if _, _, err := QuickTunnel(context.Background(), DefaultListen); err == nil {
		t.Error("no address, no tunnel")
	}
}

func TestConfigAndRemotes(t *testing.T) {
	dir := t.TempDir()
	c1, created, err := LoadOrCreate(filepath.Join(dir, "agent.json"), false)
	if err != nil || !created || len(c1.Token) < 30 {
		t.Fatalf("%+v %v %v", c1, created, err)
	}
	c2, created, _ := LoadOrCreate(filepath.Join(dir, "agent.json"), false)
	if created || c2.Token != c1.Token {
		t.Error("the token is kept")
	}
	c3, _, _ := LoadOrCreate(filepath.Join(dir, "agent.json"), true)
	if c3.Token == c1.Token {
		t.Error("--rotate-token makes a new one")
	}
	p := filepath.Join(dir, "agents.json")
	rs, _ := LoadRemotes(p)
	rs["vps"] = Remote{Name: "vps", URL: "https://a.test", Token: "x"}
	if err := rs.Save(p); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("the agents list holds tokens; mode %v", st.Mode())
	}
	back, _ := LoadRemotes(p)
	if back["vps"].URL != "https://a.test" || len(back.Names()) != 1 {
		t.Errorf("%+v", back)
	}
	for in, ok := range map[string]bool{"https://agent.example.com/": true, "http://127.0.0.1:5299": true, "http://agent.example.com": false, "agent.example.com": false} {
		if _, err := CheckURL(in); (err == nil) != ok {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestAccessHeaders(t *testing.T) {
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Clone()
		w.Write([]byte(`{"agent":"netcheck"}`))
	}))
	defer srv.Close()
	r := Remote{URL: srv.URL, Token: "tok", AccessID: "id.access", AccessSecret: "sec"}
	if _, err := r.Hello(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got.Get("CF-Access-Client-Id") != "id.access" || got.Get("CF-Access-Client-Secret") != "sec" || got.Get("Authorization") != "Bearer tok" {
		t.Errorf("headers: %v", got)
	}
}
