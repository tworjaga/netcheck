// Package webx holds the web tools: an HTTP request broken into its
// phases, and a close look at any server's TLS certificate.
package webx

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"time"
)

// Phases of one request, measured from its start.
type Phases struct {
	DNS      time.Duration `json:"dns_ns"`
	Connect  time.Duration `json:"connect_ns"`
	TLS      time.Duration `json:"tls_ns"`
	Wait     time.Duration `json:"wait_ns"` // request sent → first byte: the server's time
	Download time.Duration `json:"download_ns"`
	Total    time.Duration `json:"total_ns"`
}

// TTFB is the time to the first byte of the answer.
func (p Phases) TTFB() time.Duration { return p.DNS + p.Connect + p.TLS + p.Wait }

// Hop is one request and its answer: a redirect, or the final page.
type Hop struct {
	Method     string      `json:"method"`
	URL        string      `json:"url"`
	Status     int         `json:"status,omitempty"`
	StatusText string      `json:"status_text,omitempty"`
	Proto      string      `json:"proto,omitempty"`
	Remote     string      `json:"remote,omitempty"`
	TLSVersion string      `json:"tls_version,omitempty"`
	Location   string      `json:"location,omitempty"`
	Header     http.Header `json:"headers,omitempty"`
	Size       int64       `json:"size"` // bytes of body as sent (compressed, if it was)
	Body       []byte      `json:"-"`    // with Options.KeepBody: the start of the body, decoded
	Encoding   string      `json:"encoding,omitempty"`
	Phases     Phases      `json:"timing"`
	Error      string      `json:"error,omitempty"`
}

// Options shape a request.
type Options struct {
	Method     string
	Header     http.Header
	Body       string
	Insecure   bool // don't check the certificate
	NoFollow   bool
	HTTP1      bool
	Family     string // "", "4" or "6"
	UserAgent  string
	Timeout    time.Duration // per hop; 0 = 15 s
	MaxBody    int64         // bytes read at most; 0 = 50 MB
	MaxHops    int           // redirects followed at most; 0 = 10
	KeepBody   int64         // keep this many bytes of the final body (asks for gzip only, to decode it)
	resolveRaw func(ctx context.Context, network, addr string) (net.Conn, error)
	tlsConfig  *tls.Config // tests: trust a local server
}

// Result is the whole exchange.
type Result struct {
	Hops  []Hop         `json:"hops"`
	Total time.Duration `json:"total_ns"`
	Error string        `json:"error,omitempty"`
}

// Final is the last hop: the page, or the hop that failed.
func (r Result) Final() Hop {
	if len(r.Hops) == 0 {
		return Hop{}
	}
	return r.Hops[len(r.Hops)-1]
}

var tlsNames = map[uint16]string{tls.VersionTLS10: "TLS 1.0", tls.VersionTLS11: "TLS 1.1", tls.VersionTLS12: "TLS 1.2", tls.VersionTLS13: "TLS 1.3"}

// TLSName is a TLS version's usual name.
func TLSName(v uint16) string {
	if n, ok := tlsNames[v]; ok {
		return n
	}
	return fmt.Sprintf("0x%04x", v)
}

// NormalizeURL adds https:// to a bare host.
func NormalizeURL(s string) (*url.URL, error) {
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("%s: only http:// and https:// URLs", s)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%s: no host", s)
	}
	if u.Path == "" {
		u.Path = "/"
	}
	return u, nil
}

// one sends a single request on a new connection, timing each phase.
func one(ctx context.Context, method string, u *url.URL, body string, o Options) Hop {
	h := Hop{Method: method, URL: u.String()}
	var t0, dnsS, dnsE, conS, conE, tlsS, tlsE, wrote, first time.Time
	trace := &httptrace.ClientTrace{
		DNSStart:             func(httptrace.DNSStartInfo) { dnsS = time.Now() },
		DNSDone:              func(httptrace.DNSDoneInfo) { dnsE = time.Now() },
		ConnectStart:         func(string, string) { conS = time.Now() },
		ConnectDone:          func(string, string, error) { conE = time.Now() },
		TLSHandshakeStart:    func() { tlsS = time.Now() },
		TLSHandshakeDone:     func(tls.ConnectionState, error) { tlsE = time.Now() },
		GotConn:              func(i httptrace.GotConnInfo) { h.Remote = i.Conn.RemoteAddr().String() },
		WroteRequest:         func(httptrace.WroteRequestInfo) { wrote = time.Now() },
		GotFirstResponseByte: func() { first = time.Now() },
	}
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), method, u.String(), rd)
	if err != nil {
		h.Error = err.Error()
		return h
	}
	for k, vs := range o.Header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", o.UserAgent)
	}
	// Ask for what browsers ask for, and count the bytes as sent.
	if req.Header.Get("Accept-Encoding") == "" {
		if o.KeepBody > 0 {
			req.Header.Set("Accept-Encoding", "gzip") // the one the standard library can decode
		} else {
			req.Header.Set("Accept-Encoding", "gzip, deflate, br, zstd")
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "*/*")
	}
	if host := o.Header.Get("Host"); host != "" {
		req.Host = host
	}
	d := &net.Dialer{Timeout: o.Timeout}
	network := "tcp" + o.Family
	tc := &tls.Config{InsecureSkipVerify: o.Insecure}
	if o.tlsConfig != nil {
		tc = o.tlsConfig.Clone()
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			if o.resolveRaw != nil {
				return o.resolveRaw(ctx, network, addr)
			}
			return d.DialContext(ctx, network, addr)
		},
		TLSClientConfig:    tc,
		DisableKeepAlives:  true,
		DisableCompression: true,
		ForceAttemptHTTP2:  !o.HTTP1,
	}
	if o.HTTP1 {
		tr.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	}
	defer tr.CloseIdleConnections()
	t0 = time.Now()
	res, err := tr.RoundTrip(req)
	if err != nil {
		h.Error = explain(err)
		h.Phases = phases(t0, dnsS, dnsE, conS, conE, tlsS, tlsE, wrote, first, time.Now())
		return h
	}
	var kept bytes.Buffer
	var sink io.Writer = io.Discard
	if o.KeepBody > 0 {
		sink = &kept
	}
	n, rerr := io.Copy(sink, io.LimitReader(res.Body, o.MaxBody))
	if o.KeepBody > 0 {
		var body io.Reader = &kept
		if strings.EqualFold(res.Header.Get("Content-Encoding"), "gzip") {
			if zr, err := gzip.NewReader(&kept); err == nil {
				body = zr
			}
		}
		h.Body, _ = io.ReadAll(io.LimitReader(body, o.KeepBody))
	}
	res.Body.Close()
	end := time.Now()
	h.Status, h.StatusText, h.Proto, h.Size = res.StatusCode, http.StatusText(res.StatusCode), res.Proto, n
	h.Header, h.Encoding, h.Location = res.Header, res.Header.Get("Content-Encoding"), res.Header.Get("Location")
	if res.TLS != nil {
		h.TLSVersion = TLSName(res.TLS.Version)
	}
	if rerr != nil {
		h.Error = "the body broke off: " + explain(rerr)
	}
	h.Phases = phases(t0, dnsS, dnsE, conS, conE, tlsS, tlsE, wrote, first, end)
	return h
}

func span(a, b time.Time) time.Duration {
	if a.IsZero() || b.IsZero() || b.Before(a) {
		return 0
	}
	return b.Sub(a)
}

func phases(t0, dnsS, dnsE, conS, conE, tlsS, tlsE, wrote, first, end time.Time) Phases {
	p := Phases{DNS: span(dnsS, dnsE), Connect: span(conS, conE), TLS: span(tlsS, tlsE), Total: span(t0, end)}
	p.Wait = span(wrote, first)
	p.Download = span(first, end)
	return p
}

// explain makes the usual errors read like sentences.
func explain(err error) string {
	var dns *net.DNSError
	var cert *tls.CertificateVerificationError
	var op *net.OpError
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "no answer in time"
	case errors.As(err, &dns):
		if dns.IsNotFound {
			return dns.Name + " doesn't exist"
		}
		return "couldn't look up " + dns.Name
	case errors.As(err, &cert):
		var hn x509.HostnameError
		var inv x509.CertificateInvalidError
		var ua x509.UnknownAuthorityError
		leaf := cert.UnverifiedCertificates
		switch {
		case errors.As(cert.Err, &inv) && inv.Reason == x509.Expired && len(leaf) > 0 && time.Now().After(leaf[0].NotAfter):
			return "the certificate expired on " + leaf[0].NotAfter.UTC().Format("2006-01-02") + " (netcheck cert shows the details; -k skips the check)"
		case errors.As(cert.Err, &hn):
			return "the certificate is for another name (netcheck cert shows which; -k skips the check)"
		case errors.As(cert.Err, &ua):
			return "the certificate isn't trusted (netcheck cert shows why; -k skips the check)"
		}
		return "certificate problem: " + cert.Err.Error()
	case errors.As(err, &op) && op.Op == "dial":
		if strings.Contains(err.Error(), "refused") {
			return "connection refused"
		}
		return "couldn't connect: " + op.Err.Error()
	}
	return err.Error()
}

// Fetch requests a URL, following redirects one hop at a time so each gets
// its own timing.
func Fetch(ctx context.Context, rawURL string, o Options) Result {
	if o.Method == "" {
		o.Method = "GET"
		if o.Body != "" {
			o.Method = "POST"
		}
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.MaxBody == 0 {
		o.MaxBody = 50 << 20
	}
	if o.MaxHops == 0 {
		o.MaxHops = 10
	}
	var r Result
	u, err := NormalizeURL(rawURL)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	method, body := o.Method, o.Body
	seen := map[string]bool{}
	for ctx.Err() == nil {
		h := one(ctx, method, u, body, o)
		r.Hops = append(r.Hops, h)
		r.Total += h.Phases.Total
		if h.Error != "" {
			r.Error = h.Error
			return r
		}
		if o.NoFollow || h.Status < 300 || h.Status > 399 || h.Location == "" {
			return r
		}
		next, err := u.Parse(h.Location)
		if err != nil {
			r.Error = "bad redirect: " + h.Location
			return r
		}
		seen[u.String()] = true
		if seen[next.String()] {
			r.Error = "redirect loop back to " + next.String()
			return r
		}
		if len(r.Hops) > o.MaxHops {
			r.Error = fmt.Sprintf("more than %d redirects", o.MaxHops)
			return r
		}
		// 301-303 turn a POST into a GET; 307 and 308 keep it.
		if h.Status != 307 && h.Status != 308 {
			if method != "GET" && method != "HEAD" {
				method = "GET"
			}
			body = ""
		}
		u = next
	}
	r.Error = "interrupted"
	return r
}
