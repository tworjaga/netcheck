// Package agent lets netcheck run checks from another machine. The agent
// listens on 127.0.0.1 only; cloudflared (a Cloudflare Tunnel) carries
// requests to it, so the server opens no port and Cloudflare provides
// HTTPS. Every request needs the agent's token, and only a fixed list of
// read-only checks can run.
package agent

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/uptime"
)

// DefaultListen is where the agent waits for cloudflared.
const DefaultListen = "127.0.0.1:5299"

// Tools the agent runs on request: checks that only look.
var Tools = map[string]bool{
	"ping": true, "dig": true, "dnstrace": true, "propagate": true, "http": true, "cert": true, "trace": true,
	"whois": true, "site": true, "domain": true, "mail": true, "reach": true, "route": true, "dns": true,
	"ip": true, "tls": true, "mtu": true, "uptime": true, "connect": true,
}

// deniedFlags would read or write files on the agent, run for ever, or
// send alerts from it.
var deniedFlags = map[string]bool{
	"f": true, "o": true, "watch": true, "report": true, "notify": true, "webhook": true, "alert-cmd": true,
	"email": true, "smtp": true, "smtp-user": true, "email-from": true, "test-alert": true, "helper": true,
	"server": true,
}

// CheckArgs refuses tools and flags the agent won't run.
func CheckArgs(tool string, args []string) error {
	if !Tools[tool] {
		return fmt.Errorf("the agent doesn't run %q; it runs %s", tool, toolList())
	}
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || a == "-" {
			continue
		}
		name := strings.TrimLeft(a, "-")
		name, _, _ = strings.Cut(name, "=")
		if deniedFlags[name] {
			return fmt.Errorf("-%s isn't allowed on the agent", name)
		}
	}
	if tool == "uptime" {
		once := false
		for _, a := range args {
			once = once || strings.TrimLeft(a, "-") == "once"
		}
		if !once {
			return fmt.Errorf("uptime runs on the agent only with --once")
		}
	}
	if tool == "connect" {
		for _, a := range args {
			if strings.TrimLeft(a, "-") == "s" {
				return nil
			}
		}
		return fmt.Errorf("connect runs on the agent only with -s (it can't be typed at)")
	}
	return nil
}

func toolList() string {
	var t []string
	for k := range Tools {
		t = append(t, k)
	}
	sortStrings(t)
	return strings.Join(t, ", ")
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// NewToken makes a random token.
func NewToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- the server ---

// RunRequest asks the agent to run one check.
type RunRequest struct {
	Tool string   `json:"tool"`
	Args []string `json:"args"`
	JSON bool     `json:"json"`
}

// RunResult is what the check printed, and how it ended.
type RunResult struct {
	Output string        `json:"output"`
	Exit   int           `json:"exit"`
	Took   time.Duration `json:"took_ns"`
	Host   string        `json:"host"`
}

// Hello is the agent introducing itself.
type Hello struct {
	Agent   string    `json:"agent"`
	Version string    `json:"version"`
	Host    string    `json:"host"`
	OS      string    `json:"os"`
	Time    time.Time `json:"time"`
	Caller  string    `json:"caller_ip"` // the address the agent sees the caller at
}

// PortResult is a check of the caller's own port, from the agent.
type PortResult struct {
	IP    string `json:"ip"`
	Port  int    `json:"port"`
	Open  bool   `json:"open"`
	Error string `json:"error,omitempty"`
}

// Status is what the agent is doing besides answering: since when it
// runs, its quick tunnel, and the targets it watches around the clock.
type Status struct {
	Since  time.Time      `json:"since"`
	Tunnel string         `json:"tunnel,omitempty"`
	Every  time.Duration  `json:"every_ns,omitempty"`
	Alerts []string       `json:"alerts,omitempty"`
	Watch  []uptime.State `json:"watch,omitempty"`
	Events []uptime.Event `json:"events,omitempty"`
}

// Server is the agent's HTTP side.
type Server struct {
	Token   string
	Version string
	OS      string
	// Run executes a check; by default, this netcheck binary.
	Run func(ctx context.Context, tool string, args []string, json bool) (string, int)
	// DialBack tries the caller's port (a seam for tests).
	DialBack func(ctx context.Context, addr string) bool
	Log      func(string)
	// Status describes the agent for /v1/status (what it watches).
	Status func() Status

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// RunSelf runs this executable with the tool and arguments, as the agent
// does by default. Output is plain text (or JSON) since it isn't a
// terminal.
func RunSelf(ctx context.Context, tool string, args []string, asJSON bool) (string, int) {
	exe, err := os.Executable()
	if err != nil {
		return "the agent can't find its own program: " + err.Error(), 1
	}
	all := append([]string{tool}, args...)
	if asJSON {
		all = append(all, "--json")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, all...)
	cmd.Env = append(os.Environ(), "NO_COLOR=1", "NETCHECK_AGENT_CHILD=1")
	out, err := cmd.CombinedOutput()
	code := 0
	var ee *exec.ExitError
	switch {
	case errors.As(err, &ee):
		code = ee.ExitCode()
	case err != nil:
		return err.Error(), 1
	}
	if len(out) > 1<<20 {
		out = out[:1<<20]
	}
	return string(out), code
}

// allow is a small rate limit: 30 requests a minute, bursts of 10.
func (s *Server) allow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.last.IsZero() {
		s.tokens = 10
	} else {
		s.tokens = min(10, s.tokens+now.Sub(s.last).Seconds()*0.5)
	}
	s.last = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// callerIP is who sent the request: cloudflared passes the visitor's
// address in CF-Connecting-IP; it counts only when the request came from
// this machine (cloudflared), never from outside.
func callerIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); net.ParseIP(cf) != nil {
			return cf
		}
	}
	return host
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (s *Server) logf(format string, a ...any) {
	if s.Log != nil {
		s.Log(fmt.Sprintf(format, a...))
	}
}

// ServeHTTP answers /v1/hello, /v1/status, /v1/run and /v1/port.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.Token == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "wrong or missing token"})
		return
	}
	if !s.allow() {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many requests; slow down"})
		return
	}
	host, _ := os.Hostname()
	switch r.URL.Path {
	case "/v1/hello":
		writeJSON(w, 200, Hello{Agent: "netcheck", Version: s.Version, Host: host, OS: s.OS, Time: time.Now(), Caller: callerIP(r)})
	case "/v1/status":
		var st Status
		if s.Status != nil {
			st = s.Status()
		}
		writeJSON(w, 200, st)
	case "/v1/run":
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST"})
			return
		}
		var req RunRequest
		if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
			writeJSON(w, 400, map[string]string{"error": "bad request"})
			return
		}
		if err := CheckArgs(req.Tool, req.Args); err != nil {
			writeJSON(w, 403, map[string]string{"error": err.Error()})
			return
		}
		run := s.Run
		if run == nil {
			run = RunSelf
		}
		start := time.Now()
		s.logf("run %s %s for %s", req.Tool, strings.Join(req.Args, " "), callerIP(r))
		out, code := run(r.Context(), req.Tool, req.Args, req.JSON)
		writeJSON(w, 200, RunResult{Output: out, Exit: code, Took: time.Since(start), Host: host})
	case "/v1/port":
		port, err := strconv.Atoi(r.URL.Query().Get("port"))
		if err != nil || port < 1 || port > 65535 {
			writeJSON(w, 400, map[string]string{"error": "port is 1 to 65535"})
			return
		}
		ip := callerIP(r)
		res := PortResult{IP: ip, Port: port}
		if p := net.ParseIP(ip); p == nil || p.IsLoopback() || p.IsPrivate() {
			res.Error = "the agent sees you at " + ip + ", a local address; run it where it reaches you over the internet (through the tunnel)"
			writeJSON(w, 200, res)
			return
		}
		dial := s.DialBack
		if dial == nil {
			dial = func(ctx context.Context, addr string) bool {
				d := net.Dialer{Timeout: 5 * time.Second}
				c, err := d.DialContext(ctx, "tcp", addr)
				if err == nil {
					c.Close()
				}
				return err == nil
			}
		}
		s.logf("port check of %s:%d", ip, port)
		res.Open = dial(r.Context(), net.JoinHostPort(ip, strconv.Itoa(port)))
		writeJSON(w, 200, res)
	default:
		writeJSON(w, 404, map[string]string{"error": "not found"})
	}
}

// CheckListen refuses addresses other machines could reach: the tunnel
// is the way in.
func CheckListen(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%q: give host:port, like 127.0.0.1:5299", addr)
	}
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("the agent listens on this machine only (127.0.0.1 or ::1); cloudflared brings requests to it")
	}
	return nil
}

// --- the quick tunnel ---

var trycloudflare = regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`)

// startCloudflared is a test seam.
var startCloudflared = func(ctx context.Context, target string) (io.ReadCloser, func() error, error) {
	path, err := exec.LookPath("cloudflared")
	if err != nil {
		return nil, nil, fmt.Errorf("cloudflared isn't installed: get it from https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/ (Windows: winget install Cloudflare.cloudflared)")
	}
	cmd := exec.CommandContext(ctx, path, "tunnel", "--no-autoupdate", "--url", "http://"+target)
	out, err := cmd.StderrPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, cmd.Wait, nil
}

// QuickTunnel starts a cloudflared quick tunnel to target and returns its
// public address. The tunnel lives as long as ctx.
func QuickTunnel(ctx context.Context, target string) (string, <-chan error, error) {
	out, wait, err := startCloudflared(ctx, target)
	if err != nil {
		return "", nil, err
	}
	found := make(chan string, 1)
	done := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(out)
		sent := false
		for sc.Scan() {
			if m := trycloudflare.FindString(sc.Text()); m != "" && !sent {
				found <- m
				sent = true
			}
		}
		done <- wait()
	}()
	select {
	case u := <-found:
		return u, done, nil
	case err := <-done:
		if err == nil {
			err = errors.New("cloudflared stopped without giving an address")
		}
		return "", nil, fmt.Errorf("cloudflared: %v", err)
	case <-time.After(45 * time.Second):
		return "", nil, errors.New("cloudflared didn't give an address within 45 s")
	case <-ctx.Done():
		return "", nil, ctx.Err()
	}
}

// --- the agent's own settings ---

// Config is the agent's side: its token.
type Config struct {
	Token string `json:"token"`
}

// ConfigPath is os.UserConfigDir()/netcheck/agent.json, or
// NETCHECK_AGENT_CONFIG.
func ConfigPath() (string, error) {
	if p := os.Getenv("NETCHECK_AGENT_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "agent.json"), nil
}

// LoadOrCreate reads the agent's token, making one the first time (or
// when rotate is set).
func LoadOrCreate(path string, rotate bool) (Config, bool, error) {
	var c Config
	if b, err := os.ReadFile(path); err == nil && !rotate {
		if json.Unmarshal(b, &c) == nil && c.Token != "" {
			return c, false, nil
		}
	}
	c.Token = NewToken()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return c, true, err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return c, true, os.WriteFile(path, b, 0o600)
}

// EnvPath is agent.env beside the agent's settings: variables the agent
// needs when it runs as a service, which doesn't see the shell's
// environment (NETCHECK_SMTP_PASSWORD for email alerts).
func EnvPath(config string) string { return filepath.Join(filepath.Dir(config), "agent.env") }

// LoadEnv sets the variables in path (KEY=VALUE lines) that aren't set
// already. A missing file is fine.
func LoadEnv(path string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), "=")
		if !ok || strings.HasPrefix(k, "#") || k == "" {
			continue
		}
		if _, set := os.LookupEnv(k); !set {
			os.Setenv(k, v)
		}
	}
}

// SaveEnv writes the variables, readable by this user only.
func SaveEnv(path string, vars map[string]string) error {
	var b strings.Builder
	b.WriteString("# netcheck agent: read when it starts\n")
	for _, k := range sortedKeys(vars) {
		b.WriteString(k + "=" + vars[k] + "\n")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

func sortedKeys(m map[string]string) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sortStrings(k)
	return k
}

// LoadConfig reads the agent's settings without making any.
func LoadConfig(path string) (Config, error) {
	var c Config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	return c, json.Unmarshal(b, &c)
}

// PIDPath is agent.pid beside the agent's settings: the running agent.
func PIDPath(config string) string { return filepath.Join(filepath.Dir(config), "agent.pid") }
