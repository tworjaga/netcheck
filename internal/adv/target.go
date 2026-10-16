// Package adv holds what every Advanced-mode tool shares: reading targets,
// --fail-on rules, the --authorized scope check and pacing, the JSON
// envelope, --watch, and the common flags.
package adv

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Target is one thing a tool checks: a host with an optional port, a URL,
// or one address out of a CIDR range.
type Target struct {
	Raw    string `json:"target"`           // as the user wrote it
	Scheme string `json:"scheme,omitempty"` // "https" for https://…
	Host   string `json:"host"`             // name or address, no brackets
	Port   int    `json:"port,omitempty"`   // 0: the tool's default
	Path   string `json:"path,omitempty"`   // for URLs
}

// Addr is host:port, using def when the target has no port.
func (t Target) Addr(def int) string {
	p := t.Port
	if p == 0 {
		p = def
	}
	return net.JoinHostPort(t.Host, strconv.Itoa(p))
}

// IP is the target's address when it's a literal one, else nil.
func (t Target) IP() net.IP { return net.ParseIP(t.Host) }

// defaultPorts fills in the port a URL scheme implies.
var defaultPorts = map[string]int{"http": 80, "https": 443}

// Parse reads one target: "host", "host:port", "[v6]:port", a bare IPv6
// address, or "scheme://host[:port][/path]".
func Parse(s string) (Target, error) {
	s = strings.TrimSpace(s)
	t := Target{Raw: s}
	if s == "" {
		return t, errors.New("empty target")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Hostname() == "" {
			return t, fmt.Errorf("%q isn't a valid URL", s)
		}
		t.Scheme, t.Host, t.Path = strings.ToLower(u.Scheme), u.Hostname(), u.EscapedPath()
		if p := u.Port(); p != "" {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				return t, fmt.Errorf("%q has a bad port", s)
			}
			t.Port = n
		} else {
			t.Port = defaultPorts[t.Scheme]
		}
		return t, nil
	}
	if ip := net.ParseIP(s); ip != nil { // a bare IPv6 address has colons too
		t.Host = ip.String()
		return t, nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		if strings.Contains(s, ":") && !strings.HasPrefix(s, "[") {
			return t, fmt.Errorf("%q isn't a host or host:port", s)
		}
		t.Host = strings.Trim(s, "[]")
		return t, validHost(t)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return t, fmt.Errorf("%q has a bad port", s)
	}
	t.Host, t.Port = host, n
	return t, validHost(t)
}

func validHost(t Target) error {
	if t.Host == "" || strings.ContainsAny(t.Host, " /\\") {
		return fmt.Errorf("%q isn't a valid host", t.Raw)
	}
	return nil
}

// MaxExpand caps how many addresses one CIDR range may turn into.
const MaxExpand = 4096

// Expand turns a CIDR range ("10.0.0.0/24", optionally with ":port") into
// one target per usable address; anything else comes back as is.
func Expand(s string) ([]Target, error) {
	s = strings.TrimSpace(s)
	cidr, port := s, 0
	if i := strings.LastIndex(s, ":"); i > 0 && strings.Contains(s[:i], "/") && !strings.Contains(s[:i], ":") {
		cidr = s[:i]
		n, err := strconv.Atoi(s[i+1:])
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("%q has a bad port", s)
		}
		port = n
	}
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		t, err := Parse(s)
		if err != nil {
			return nil, err
		}
		return []Target{t}, nil
	}
	ones, bits := n.Mask.Size()
	if bits-ones > 12 { // more than 4096 addresses
		return nil, fmt.Errorf("%s is too large (more than %d addresses)", cidr, MaxExpand)
	}
	var out []Target
	base := n.IP.Mask(n.Mask)
	for cur := dup(base); n.Contains(cur); inc(cur) {
		// Skip the network and broadcast addresses of IPv4 ranges below /31.
		if ip.To4() != nil && bits-ones >= 2 && (cur.Equal(base) || isBroadcast(cur, n)) {
			continue
		}
		out = append(out, Target{Raw: s, Host: cur.String(), Port: port})
	}
	return out, nil
}

func dup(ip net.IP) net.IP { return append(net.IP(nil), ip...) }

func inc(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		if ip[i]++; ip[i] != 0 {
			return
		}
	}
}

func isBroadcast(ip net.IP, n *net.IPNet) bool {
	for i := range n.Mask {
		if ip[len(ip)-len(n.Mask)+i]|n.Mask[i] != 0xff {
			return false
		}
	}
	return true
}

// ReadList reads targets from r: one per line, blank lines and "#" comments
// ignored, ranges expanded.
func ReadList(r io.Reader) ([]Target, error) {
	var out []Target
	sc := bufio.NewScanner(r)
	for line := 1; sc.Scan(); line++ {
		s := sc.Text()
		if i := strings.Index(s, "#"); i >= 0 {
			s = s[:i]
		}
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		ts, err := Expand(s)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, ts...)
	}
	return out, sc.Err()
}

// Targets gathers what a tool should check: its arguments, plus the lines
// of file when -f is given.
func Targets(args []string, file string) ([]Target, error) {
	var out []Target
	for _, a := range args {
		ts, err := Expand(a)
		if err != nil {
			return nil, err
		}
		out = append(out, ts...)
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		ts, err := ReadList(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		out = append(out, ts...)
	}
	return out, nil
}
