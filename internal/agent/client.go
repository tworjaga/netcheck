package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Remote is one agent this machine knows.
type Remote struct {
	Name         string `json:"name"`
	URL          string `json:"url"`
	Token        string `json:"token"`
	AccessID     string `json:"cf_access_client_id,omitempty"`
	AccessSecret string `json:"cf_access_client_secret,omitempty"`
}

// Remotes is the list of known agents, by name.
type Remotes map[string]Remote

// RemotesPath is os.UserConfigDir()/netcheck/agents.json, or
// NETCHECK_AGENTS.
func RemotesPath() (string, error) {
	if p := os.Getenv("NETCHECK_AGENTS"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "netcheck", "agents.json"), nil
}

// LoadRemotes reads the list; a missing file is an empty list.
func LoadRemotes(path string) (Remotes, error) {
	r := Remotes{}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return r, nil
	}
	if err != nil {
		return r, err
	}
	return r, json.Unmarshal(b, &r)
}

// Save writes the list, readable by this user only (it holds tokens).
func (r Remotes) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(r, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

// Names lists the agents in order.
func (r Remotes) Names() []string {
	var n []string
	for k := range r {
		n = append(n, k)
	}
	sort.Strings(n)
	return n
}

// CheckURL accepts https:// addresses (http:// only for this machine).
func CheckURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("%q isn't an address; give the tunnel's https:// address", raw)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1"):
	default:
		return "", fmt.Errorf("%q: use the tunnel's https:// address; the token mustn't travel unencrypted", raw)
	}
	return u.String(), nil
}

// client is a test seam.
var client = &http.Client{Timeout: 4 * time.Minute}

func (r Remote) do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, r.URL+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	req.Header.Set("Content-Type", "application/json")
	if r.AccessID != "" {
		req.Header.Set("CF-Access-Client-Id", r.AccessID)
		req.Header.Set("CF-Access-Client-Secret", r.AccessSecret)
	}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("can't reach the agent at %s: %v", r.URL, err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if res.StatusCode != 200 {
		var e struct{ Error string }
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			return fmt.Errorf("the agent refused: %s", e.Error)
		}
		if res.StatusCode == 403 || res.StatusCode == 302 || strings.Contains(string(b), "cloudflareaccess") {
			return fmt.Errorf("Cloudflare Access stopped the request (%s); add the service token with --access-id and --access-secret", res.Status)
		}
		return fmt.Errorf("the agent answered %s", res.Status)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("that isn't a netcheck agent (unexpected answer)")
	}
	return nil
}

// Hello asks the agent who it is.
func (r Remote) Hello(ctx context.Context) (Hello, error) {
	var h Hello
	err := r.do(ctx, "GET", "/v1/hello", nil, &h)
	if err == nil && h.Agent != "netcheck" {
		err = fmt.Errorf("that isn't a netcheck agent")
	}
	return h, err
}

// Run has the agent run a check.
func (r Remote) Run(ctx context.Context, tool string, args []string, asJSON bool) (RunResult, error) {
	var res RunResult
	err := r.do(ctx, "POST", "/v1/run", RunRequest{Tool: tool, Args: args, JSON: asJSON}, &res)
	return res, err
}

// Port has the agent try this machine's public address on port.
func (r Remote) Port(ctx context.Context, port int) (PortResult, error) {
	var res PortResult
	err := r.do(ctx, "GET", fmt.Sprintf("/v1/port?port=%d", port), nil, &res)
	return res, err
}

// Status asks what the agent watches.
func (r Remote) Status(ctx context.Context) (Status, error) {
	var st Status
	err := r.do(ctx, "GET", "/v1/status", nil, &st)
	return st, err
}
