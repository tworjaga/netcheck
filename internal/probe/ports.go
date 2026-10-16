package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// PortInfo is a TCP port and the service usually found on it.
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// CommonPorts are the ports a local scan checks.
var CommonPorts = []PortInfo{
	{21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"}, {80, "http"},
	{110, "pop3"}, {139, "netbios"}, {143, "imap"}, {443, "https"}, {445, "smb"},
	{548, "afp"}, {554, "rtsp"}, {631, "ipp"}, {1883, "mqtt"}, {3389, "rdp"},
	{5000, "http-alt"}, {5900, "vnc"}, {8000, "http-alt"}, {8080, "http-alt"},
	{8443, "https-alt"}, {8888, "http-alt"}, {9100, "printer"}, {32400, "plex"},
}

// IsLocalAddr reports whether ip is on a private, loopback or link-local
// network. The scanner refuses anything else: it's for your own devices.
func IsLocalAddr(ip net.IP) bool {
	return ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast())
}

// ScanPorts tries a TCP connect to each port on ip and returns those that
// accepted. Closed and filtered ports are indistinguishable and omitted.
func ScanPorts(ctx context.Context, ip string, ports []PortInfo, timeout time.Duration) []PortInfo {
	var mu sync.Mutex
	var open []PortInfo
	var wg sync.WaitGroup
	sem := make(chan struct{}, 32)
	d := net.Dialer{Timeout: timeout}
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(p PortInfo) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, fmt.Sprint(p.Port)))
			if err != nil {
				return
			}
			c.Close()
			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}

// ExternalResult is the answer from an external port-check helper.
type ExternalResult struct {
	Helper string `json:"helper"`
	IP     string `json:"ip,omitempty"` // your public address, as the helper saw it
	Port   int    `json:"port"`
	Open   bool   `json:"open"`
	Error  string `json:"error,omitempty"` // set when the check couldn't be completed
}

// ExternalCheck asks a helper whether port is reachable from the internet on
// this connection's public address.
//
// Helper protocol: GET <helper>/check?port=N answers JSON
// {"ip":"203.0.113.7","port":N,"open":true|false}. The helper connects back
// to the address the request came from, never to one the caller names, so it
// can't be used to scan other people. contrib/portcheck-helper is a
// reference implementation.
func ExternalCheck(ctx context.Context, helper string, port int) ExternalResult {
	res := ExternalResult{Helper: helper, Port: port}
	u, err := url.Parse(strings.TrimRight(helper, "/") + "/check")
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		res.Error = "the helper address isn't a valid http(s) URL"
		return res
	}
	u.RawQuery = url.Values{"port": {fmt.Sprint(port)}}.Encode()
	c, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(c, http.MethodGet, u.String(), nil)
	if err != nil {
		res.Error = "the helper address isn't a valid http(s) URL"
		return res
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		res.Error = "couldn't reach the helper (" + shortNetErr(err) + ")"
		return res
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode == http.StatusTooManyRequests {
		res.Error = "the helper is rate limiting you; try again in a minute"
		return res
	}
	var v struct {
		IP    string `json:"ip"`
		Port  int    `json:"port"`
		Open  bool   `json:"open"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		res.Error = "the helper's answer wasn't understood"
		return res
	}
	if v.Error != "" {
		res.Error = "the helper said: " + v.Error
		return res
	}
	if resp.StatusCode != http.StatusOK {
		res.Error = fmt.Sprintf("the helper answered HTTP %d", resp.StatusCode)
		return res
	}
	res.IP, res.Open = v.IP, v.Open
	return res
}

func shortNetErr(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case strings.Contains(err.Error(), "refused"):
		return "connection refused"
	case strings.Contains(err.Error(), "no such host"):
		return "unknown host"
	}
	return "network error"
}
