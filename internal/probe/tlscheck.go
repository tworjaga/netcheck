package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

// TLSProbe is one HTTPS handshake.
type TLSProbe struct {
	Host      string  `json:"host"`
	OK        bool    `json:"ok"`
	Version   string  `json:"version,omitempty"`
	Ms        float64 `json:"handshake_ms,omitempty"`
	Issuer    string  `json:"issuer,omitempty"`    // organization that issued the server's certificate
	Root      string  `json:"root,omitempty"`      // the trusted root the chain ended at
	Inspector string  `json:"inspector,omitempty"` // known interception product found in the chain
	Problem   string  `json:"problem,omitempty"`   // "untrusted", "expired", "not_yet_valid", "name", "network"
	Error     string  `json:"error,omitempty"`
}

// TLSResult covers the handshakes and the clock check.
type TLSResult struct {
	Probes []TLSProbe `json:"probes"`
	// SkewSeconds is how far this computer's clock is ahead (+) or behind
	// (−) the servers' clocks. Valid only when ClockChecked is set.
	SkewSeconds  float64 `json:"clock_skew_seconds"`
	ClockChecked bool    `json:"clock_checked"`
}

var tlsHosts = []string{"www.cloudflare.com", "www.google.com", "www.microsoft.com"}

// Products that re-sign HTTPS so they can inspect it: antivirus web shields
// and company proxies. Seeing one is expected if you installed it.
var inspectors = []string{
	"avast", "avg ", "kaspersky", "eset", "bitdefender", "sophos", "fortinet", "fortigate",
	"zscaler", "netskope", "cisco umbrella", "blue coat", "palo alto", "mcafee", "norton",
	"forcepoint", "trend micro", "symantec web", "checkpoint", "check point", "barracuda",
	"websense", "untangle", "smoothwall", "lightspeed", "securly", "goguardian", "contentkeeper",
}

func inspectorIn(certs []*x509.Certificate) string {
	for _, c := range certs {
		for _, name := range append(append([]string{c.Issuer.CommonName}, c.Issuer.Organization...), c.Subject.Organization...) {
			low := strings.ToLower(name) + " "
			for _, k := range inspectors {
				if strings.Contains(low, k) {
					return name
				}
			}
		}
	}
	return ""
}

// Public certificate authorities, matched loosely by organization or name.
// A connection whose certificate came from none of these, issuer and root
// alike, has been re-signed by something local: antivirus, a company proxy,
// or worse. The list only needs the big CAs the test sites actually use.
var publicCAs = []string{
	"google trust services", "let's encrypt", "internet security research group", "digicert",
	"microsoft", "sectigo", "comodo", "usertrust", "globalsign", "entrust", "amazon", "starfield",
	"godaddy", "go daddy", "identrust", "ssl corporation", "ssl.com", "certainly", "zerossl",
	"baltimore", "cybertrust", "quovadis", "buypass", "actalis", "harica", "certum", "asseco",
	"thawte", "geotrust", "verisign", "symantec", "cloudflare", "trustwave", "securetrust",
	"t-systems", "telesec", "swisssign", "gts root", "isrg",
}

func publicCA(name string) bool {
	low := strings.ToLower(name)
	for _, k := range publicCAs {
		if strings.Contains(low, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func org(n []string, cn string) string {
	if len(n) > 0 {
		return n[0]
	}
	return cn
}

// tlsDial is a test seam: it dials host:443 with cfg.
var tlsDial = func(ctx context.Context, host string, cfg *tls.Config) (*tls.Conn, error) {
	d := tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: cfg}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, "443"))
	if err != nil {
		return nil, err
	}
	return c.(*tls.Conn), nil
}

func classifyTLSErr(err error) string {
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var host x509.HostnameError
	var verify *tls.CertificateVerificationError
	switch {
	case errors.As(err, &unknown):
		return "untrusted"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		// Go reports "not yet valid" with the same reason; the detail says which.
		if strings.Contains(invalid.Detail, "before") {
			return "not_yet_valid"
		}
		return "expired"
	case errors.As(err, &host):
		return "name"
	case errors.As(err, &verify):
		return "untrusted"
	}
	return "network"
}

func probeTLS(ctx context.Context, host string, roots *x509.CertPool) TLSProbe {
	p := TLSProbe{Host: host}
	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	start := time.Now()
	c, err := tlsDial(ctx, host, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		p.Problem, p.Error = classifyTLSErr(err), shortErr(err)
		if p.Problem != "network" {
			// Look at what we were shown, without trusting it, to name it.
			if raw, err2 := tlsDial(ctx, host, &tls.Config{ServerName: host, InsecureSkipVerify: true}); err2 == nil {
				st := raw.ConnectionState()
				if len(st.PeerCertificates) > 0 {
					leaf := st.PeerCertificates[0]
					p.Issuer = org(leaf.Issuer.Organization, leaf.Issuer.CommonName)
				}
				p.Inspector = inspectorIn(st.PeerCertificates)
				raw.Close()
			}
		}
		return p
	}
	defer c.Close()
	p.Ms = float64(time.Since(start).Microseconds()) / 1000
	st := c.ConnectionState()
	p.OK = true
	p.Version = tls.VersionName(st.Version)
	if len(st.PeerCertificates) > 0 {
		leaf := st.PeerCertificates[0]
		p.Issuer = org(leaf.Issuer.Organization, leaf.Issuer.CommonName)
	}
	for _, chain := range st.VerifiedChains {
		if len(chain) > 0 {
			root := chain[len(chain)-1]
			p.Root = org(root.Subject.Organization, root.Subject.CommonName)
		}
		p.Inspector = inspectorIn(chain)
		break
	}
	if p.Inspector == "" && p.Issuer != "" && !publicCA(p.Issuer) && (p.Root == "" || !publicCA(p.Root)) {
		p.Inspector = p.Issuer
	}
	return p
}

// dateHeader is a test seam: the Date header and round trip of one request.
var dateHeader = func(ctx context.Context, url string) (time.Time, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return time.Time{}, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	start := time.Now()
	resp, err := noRedirect().Do(req)
	rtt := time.Since(start)
	if err != nil {
		return time.Time{}, 0, err
	}
	resp.Body.Close()
	t, err := http.ParseTime(resp.Header.Get("Date"))
	return t, rtt, err
}

// Plain HTTP on purpose: if the clock is far off, HTTPS fails before any
// Date header could be read.
var clockURLs = []string{"http://www.google.com/generate_204", "http://www.cloudflare.com/cdn-cgi/trace", "http://www.microsoft.com/"}

var now = time.Now

// clockSkew compares the local clock with several servers' Date headers and
// returns the median difference. Date has one-second resolution, so the
// result is only good to about a second.
func clockSkew(ctx context.Context) (float64, bool) {
	var skews []float64
	for _, u := range clockURLs {
		c, cancel := context.WithTimeout(ctx, 5*time.Second)
		t, rtt, err := dateHeader(c, u)
		cancel()
		if err != nil || t.IsZero() {
			continue
		}
		// The server stamped Date somewhere in the round trip; assume the middle.
		local := now().Add(-rtt / 2)
		skews = append(skews, local.Sub(t).Seconds()-0.5) // Date truncates to the second
	}
	if len(skews) == 0 {
		return 0, false
	}
	sort.Float64s(skews)
	return skews[len(skews)/2], true
}

// CheckTLS runs the handshakes and the clock check in parallel.
func CheckTLS(ctx context.Context) TLSResult {
	res := TLSResult{Probes: make([]TLSProbe, len(tlsHosts))}
	done := make(chan struct{})
	go func() {
		res.SkewSeconds, res.ClockChecked = clockSkew(ctx)
		close(done)
	}()
	for i, h := range tlsHosts {
		res.Probes[i] = probeTLS(ctx, h, tlsRoots)
	}
	<-done
	return res
}

// tlsRoots is nil (system roots) except in tests.
var tlsRoots *x509.CertPool
