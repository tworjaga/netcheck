package dnsx

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Transports.
const (
	UDP = "udp"
	TCP = "tcp"
	DoT = "dot" // DNS over TLS, RFC 7858
	DoH = "doh" // DNS over HTTPS, RFC 8484
)

// Server is where a query goes and how.
type Server struct {
	Addr      string // host:port for UDP, TCP and DoT
	URL       string // for DoH
	Transport string
	Label     string // how to show it ("1.1.1.1", "cloudflare", "system")

	tlsConfig  *tls.Config  // tests: trust a local certificate
	httpClient *http.Client // tests: DoH against a local server
}

// Name is how the server reads in output: its label, else its address.
func (s Server) Name() string {
	switch {
	case s.Label != "":
		return s.Label
	case s.Transport == DoH:
		return s.URL
	}
	// The usual port goes without saying.
	if host, port, err := net.SplitHostPort(s.Addr); err == nil && (port == "53" && s.Transport != DoT || port == "853" && s.Transport == DoT) {
		return host
	}
	return s.Addr
}

// well-known public resolvers, by short name.
var known = map[string]struct{ ip, doh string }{
	"cloudflare": {"1.1.1.1", "https://cloudflare-dns.com/dns-query"},
	"google":     {"8.8.8.8", "https://dns.google/dns-query"},
	"quad9":      {"9.9.9.9", "https://dns.quad9.net/dns-query"},
}

// ParseServer reads "1.1.1.1", "ns1.example.com:5353", "[2606:4700::1111]",
// "https://dns.example/dns-query", or a known name (cloudflare, google,
// quad9), for the given transport ("" means UDP, or DoH for a URL).
func ParseServer(s, transport string) (Server, error) {
	s = strings.TrimSpace(strings.TrimPrefix(s, "@"))
	if strings.HasPrefix(s, "https://") {
		if _, err := url.Parse(s); err != nil {
			return Server{}, fmt.Errorf("%q isn't a valid URL", s)
		}
		return Server{URL: s, Transport: DoH}, nil
	}
	if transport == "" {
		transport = UDP
	}
	label := ""
	if k, ok := known[strings.ToLower(s)]; ok {
		label = strings.ToLower(s)
		if transport == DoH {
			return Server{URL: k.doh, Transport: DoH, Label: label}, nil
		}
		s = k.ip
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	} else if strings.HasPrefix(s, "[") {
		host = strings.Trim(s, "[]")
	}
	if host == "" {
		return Server{}, fmt.Errorf("%q isn't a server", s)
	}
	if transport == DoH {
		u := "https://" + net.JoinHostPort(host, port) + "/dns-query"
		if port == "" {
			u = "https://" + bracket(host) + "/dns-query"
		}
		return Server{URL: u, Transport: DoH, Label: label}, nil
	}
	if port == "" {
		port = "53"
		if transport == DoT {
			port = "853"
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return Server{}, fmt.Errorf("%q has a bad port", s)
	}
	return Server{Addr: net.JoinHostPort(host, port), Transport: transport, Label: label}, nil
}

func bracket(h string) string {
	if strings.Contains(h, ":") {
		return "[" + h + "]"
	}
	return h
}

// Result is a sent query's answer and how it went.
type Result struct {
	Msg       *Msg
	RTT       time.Duration
	Size      int    // bytes in the answer
	Transport string // as actually used (UDP may fall back to TCP)
	Retried   bool   // the UDP answer was truncated, so TCP was used
}

func randomID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

// Exchange sends q to srv and waits up to timeout for the answer.
func Exchange(ctx context.Context, srv Server, q Query, timeout time.Duration) (*Result, error) {
	if q.ID == 0 && srv.Transport != DoH {
		q.ID = randomID() // DoH uses ID 0 so HTTP caches can share answers
	}
	msg, err := q.Pack()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	var raw []byte
	res := &Result{Transport: srv.Transport}
	switch srv.Transport {
	case UDP:
		// UDP loses a packet now and then: two tries, half the time each.
		for try := 0; try < 2; try++ {
			c, cancelTry := context.WithTimeout(ctx, timeout/2)
			raw, err = exchangeUDP(c, srv.Addr, msg)
			cancelTry()
			if err == nil || ctx.Err() != nil {
				break
			}
		}
		if err == nil && len(raw) > 2 && raw[2]&0x02 != 0 { // TC: too big for UDP
			res.Transport, res.Retried = TCP, true
			raw, err = exchangeStream(ctx, srv, msg, false)
		}
	case TCP:
		raw, err = exchangeStream(ctx, srv, msg, false)
	case DoT:
		raw, err = exchangeStream(ctx, srv, msg, true)
	case DoH:
		raw, err = exchangeHTTPS(ctx, srv, msg)
	default:
		return nil, fmt.Errorf("unknown transport %q", srv.Transport)
	}
	if err != nil {
		return nil, explain(err)
	}
	res.RTT, res.Size = time.Since(start), len(raw)
	m, err := Parse(raw)
	if err != nil && m == nil {
		return nil, err
	}
	if m.ID != q.ID {
		return nil, errors.New("the answer doesn't match the question (wrong ID)")
	}
	res.Msg = m
	return res, nil
}

// explain turns network errors into short plain sentences.
func explain(err error) error {
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, context.DeadlineExceeded):
		return errors.New("no answer (timed out)")
	case strings.Contains(err.Error(), "refused"):
		return errors.New("connection refused")
	}
	return err
}

func exchangeUDP(ctx context.Context, addr string, msg []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(msg); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		// Ignore anything that isn't the answer to this question.
		if n >= 12 && bytes.Equal(buf[:2], msg[:2]) && buf[2]&0x80 != 0 {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

// exchangeStream speaks DNS over TCP, or over TLS when secure is set: each
// message is preceded by its length as two bytes.
func exchangeStream(ctx context.Context, srv Server, msg []byte, secure bool) ([]byte, error) {
	var c net.Conn
	var err error
	if secure {
		host, _, _ := net.SplitHostPort(srv.Addr)
		cfg := srv.tlsConfig
		if cfg == nil {
			cfg = &tls.Config{MinVersion: tls.VersionTLS12}
		}
		cfg = cfg.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = host // IP addresses are checked against the certificate's IP names
		}
		d := tls.Dialer{Config: cfg}
		c, err = d.DialContext(ctx, "tcp", srv.Addr)
	} else {
		var d net.Dialer
		c, err = d.DialContext(ctx, "tcp", srv.Addr)
	}
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(c, l[:]); err != nil {
		return nil, err
	}
	out := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(c, out)
	return out, err
}

func exchangeHTTPS(ctx context.Context, srv Server, msg []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	client := srv.httpClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			Proxy:             http.ProxyFromEnvironment,
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
		}}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the DoH server answered HTTP %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/dns-message") {
		return nil, fmt.Errorf("the DoH server sent %q, not a DNS message", ct)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 65535))
}
