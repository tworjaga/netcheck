package probe

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Resolver is a DNS server to test. An empty Addr means the OS default
// resolver (used when the system's nameservers can't be read).
type Resolver struct {
	Label string `json:"label"`
	Addr  string `json:"addr"`
	Port  string `json:"-"` // defaults to 53; overridable for tests
}

// DNSResult is the outcome of testing one resolver.
type DNSResult struct {
	Label      string  `json:"label"`
	Addr       string  `json:"addr"`
	Lookups    int     `json:"lookups"`
	Answered   int     `json:"answered"`
	MedianMs   float64 `json:"median_ms"`
	RewritesNX bool    `json:"rewrites_nxdomain"`
	Error      string  `json:"error,omitempty"`
}

// DefaultNames are looked up to measure resolver latency.
var DefaultNames = []string{"example.com.", "cloudflare.com.", "wikipedia.org."}

func (r Resolver) resolver() *net.Resolver {
	if r.Addr == "" {
		return net.DefaultResolver
	}
	port := r.Port
	if port == "" {
		port = "53"
	}
	target := net.JoinHostPort(r.Addr, port)
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, network, target)
		},
	}
}

// SystemNameservers reads the nameservers the OS is configured to use
// (Linux and macOS; empty elsewhere).
func SystemNameservers() []string {
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		f := strings.Fields(ln)
		if len(f) >= 2 && f[0] == "nameserver" {
			out = append(out, f[1])
		}
	}
	return out
}

// BuildResolvers returns the system resolver first, then well-known public
// ones to compare it against.
func BuildResolvers(gw net.IP) []Resolver {
	var out []Resolver
	seen := map[string]bool{}
	if ns := SystemNameservers(); len(ns) > 0 {
		label := "System"
		if gw != nil && ns[0] == gw.String() {
			label = "Router"
		}
		out = append(out, Resolver{Label: label, Addr: ns[0]})
		seen[ns[0]] = true
	} else {
		out = append(out, Resolver{Label: "System"})
	}
	for _, p := range []Resolver{
		{Label: "Cloudflare", Addr: "1.1.1.1"},
		{Label: "Google", Addr: "8.8.8.8"},
		{Label: "Quad9", Addr: "9.9.9.9"},
	} {
		if !seen[p.Addr] {
			out = append(out, p)
		}
	}
	return out
}

func randomName() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "nx" + hex.EncodeToString(b) + ".com."
}

func shortErr(err error) string {
	var de *net.DNSError
	if errors.As(err, &de) {
		switch {
		case de.IsTimeout:
			return "timed out"
		case de.IsNotFound:
			return "no such domain"
		}
	}
	s := strings.ToLower(err.Error())
	switch {
	case strings.Contains(s, "timeout"):
		return "timed out"
	case strings.Contains(s, "refused"):
		return "connection refused"
	case strings.Contains(s, "unreachable"):
		return "unreachable"
	}
	return "no answer"
}

// systemLookup, where set, resolves through the OS's DNS servers without its
// cache (Windows). It reports whether the name has an IPv4 address.
var systemLookup func(ctx context.Context, name string) (bool, error)

// CheckResolver looks up names against r, measures the median latency, and
// checks whether it rewrites NXDOMAIN answers (a sign of ISP ad redirects).
func CheckResolver(ctx context.Context, r Resolver, names []string) DNSResult {
	res := DNSResult{Label: r.Label, Addr: r.Addr, Lookups: len(names)}
	rs := r.resolver()
	lookup := func(c context.Context, n string) (bool, error) {
		ips, err := rs.LookupIP(c, "ip4", n)
		return err == nil && len(ips) > 0, err
	}
	if r.Addr == "" && systemLookup != nil {
		lookup = systemLookup
	}
	var times []float64
	var lastErr error
	fails := 0

	for _, n := range names {
		c, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
		start := time.Now()
		ok, err := lookup(c, n)
		el := time.Since(start)
		cancel()
		if ok {
			times = append(times, float64(el.Microseconds())/1000)
			res.Answered++
			continue
		}
		lastErr = err
		if fails++; fails >= 2 && res.Answered == 0 {
			break // dead resolver: don't wait out every timeout
		}
	}
	if res.Answered == 0 {
		if lastErr != nil {
			res.Error = shortErr(lastErr)
		} else {
			res.Error = "no answer"
		}
		return res
	}
	sort.Float64s(times)
	res.MedianMs = times[len(times)/2]

	c, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	if ok, _ := lookup(c, randomName()); ok {
		res.RewritesNX = true
	}
	return res
}
