package webx

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/domain"
)

// CertInfo is one certificate of a chain, as a person reads it.
type CertInfo struct {
	Subject    string    `json:"subject"`
	Issuer     string    `json:"issuer"`
	Names      []string  `json:"names,omitempty"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	Days       int       `json:"days_left"`
	Key        string    `json:"key"`
	SigAlg     string    `json:"signature"`
	Serial     string    `json:"serial"`
	CA         bool      `json:"ca"`
	SelfSigned bool      `json:"self_signed"`
	FromStore  bool      `json:"from_trust_store,omitempty"` // the root the chain ended at, not sent by the server
}

// CertReport is what a server's TLS showed.
type CertReport struct {
	Host      string          `json:"host"`
	Port      int             `json:"port"`
	SNI       string          `json:"sni"`
	StartTLS  string          `json:"starttls,omitempty"`
	Addr      string          `json:"addr,omitempty"`
	Version   string          `json:"tls_version,omitempty"`
	Cipher    string          `json:"cipher,omitempty"`
	ALPN      string          `json:"alpn,omitempty"`
	Versions  map[string]bool `json:"versions_accepted,omitempty"`
	Chain     []CertInfo      `json:"chain"`
	Trusted   bool            `json:"trusted"`
	Problem   string          `json:"problem,omitempty"`
	OCSP      bool            `json:"ocsp_stapled"`
	CT        bool            `json:"ct_logged"`
	Checks    []domain.Check  `json:"checks"`
	Handshake time.Duration   `json:"handshake_ns"`
	Error     string          `json:"error,omitempty"`
}

// StartTLSFor is the protocol usually spoken on a port before TLS starts.
func StartTLSFor(port int) string {
	switch port {
	case 25, 587, 2525:
		return "smtp"
	case 143:
		return "imap"
	case 110:
		return "pop3"
	case 21:
		return "ftp"
	}
	return ""
}

// Test seams.
var (
	dialCert = func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 8 * time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
	certRoots *x509.CertPool // nil = the system's
	now       = time.Now
)

// startTLS speaks a protocol's plain-text opening up to the point where TLS
// begins.
func startTLS(c net.Conn, proto string) error {
	r := bufio.NewReader(c)
	c.SetDeadline(time.Now().Add(10 * time.Second))
	defer c.SetDeadline(time.Time{})
	// expect reads a reply; multi-line SMTP and FTP replies ("250-...") end
	// at the line with a space after the code.
	expect := func(ok func(string) bool) error {
		for {
			l, err := r.ReadString('\n')
			if err != nil {
				return fmt.Errorf("the server hung up during %s STARTTLS", proto)
			}
			l = strings.TrimRight(l, "\r\n")
			if len(l) > 3 && l[3] == '-' {
				continue
			}
			if !ok(l) {
				return fmt.Errorf("the server said %q", l)
			}
			return nil
		}
	}
	code := func(want string) func(string) bool { return func(l string) bool { return strings.HasPrefix(l, want) } }
	send := func(s string) { fmt.Fprint(c, s+"\r\n") }
	switch proto {
	case "smtp":
		if err := expect(code("220")); err != nil {
			return err
		}
		send("EHLO netcheck.localhost")
		if err := expect(code("250")); err != nil {
			return err
		}
		send("STARTTLS")
		return expect(code("220"))
	case "imap":
		if err := expect(code("* OK")); err != nil {
			return err
		}
		send("a1 STARTTLS")
		return expect(code("a1 OK"))
	case "pop3":
		if err := expect(code("+OK")); err != nil {
			return err
		}
		send("STLS")
		return expect(code("+OK"))
	case "ftp":
		if err := expect(code("220")); err != nil {
			return err
		}
		send("AUTH TLS")
		return expect(code("234"))
	}
	return fmt.Errorf("STARTTLS for %q isn't supported (smtp, imap, pop3, ftp)", proto)
}

// handshake connects and runs the TLS handshake (after STARTTLS if asked),
// limited to the given versions (0 = any). The certificate isn't judged
// here.
func handshake(ctx context.Context, addr, sni, proto string, minV, maxV uint16) (*tls.ConnectionState, string, time.Duration, error) {
	c, err := dialCert(ctx, addr)
	if err != nil {
		return nil, "", 0, err
	}
	defer c.Close()
	remote := c.RemoteAddr().String()
	if proto != "" {
		if err := startTLS(c, proto); err != nil {
			return nil, remote, 0, err
		}
	}
	if minV == 0 {
		minV = tls.VersionTLS10 // see what the server offers, however old
	}
	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true, MinVersion: minV, MaxVersion: maxV, NextProtos: []string{"h2", "http/1.1"}}
	if proto != "" {
		cfg.NextProtos = nil
	}
	if minV < tls.VersionTLS12 {
		// Old versions need the old cipher suites too.
		for _, s := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			cfg.CipherSuites = append(cfg.CipherSuites, s.ID)
		}
	}
	tc := tls.Client(c, cfg)
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	start := now()
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, remote, 0, err
	}
	st := tc.ConnectionState()
	return &st, remote, now().Sub(start), nil
}

func keyName(c *x509.Certificate) string {
	switch k := c.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Sprintf("RSA %d", k.N.BitLen())
	case *ecdsa.PublicKey:
		return "ECDSA " + k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519"
	}
	return c.PublicKeyAlgorithm.String()
}

// nameOf is how a certificate's subject or issuer reads: the common name,
// with the organization when it adds something.
func nameOf(n pkix.Name) string {
	cn, org := n.CommonName, n.Organization
	switch {
	case cn != "" && len(org) > 0 && !strings.Contains(cn, org[0]):
		return cn + " (" + org[0] + ")"
	case cn != "":
		return cn
	case len(org) > 0:
		return org[0]
	}
	return n.String()
}

func info(c *x509.Certificate) CertInfo {
	return CertInfo{
		Subject:   nameOf(c.Subject),
		Issuer:    nameOf(c.Issuer),
		Names:     append(append([]string{}, c.DNSNames...), ipStrings(c.IPAddresses)...),
		NotBefore: c.NotBefore, NotAfter: c.NotAfter, Days: int(c.NotAfter.Sub(now()).Hours() / 24),
		Key: keyName(c), SigAlg: c.SignatureAlgorithm.String(), Serial: fmt.Sprintf("%X", c.SerialNumber),
		CA: c.IsCA, SelfSigned: selfSigned(c),
	}
}

// selfSigned: issued by itself and signed by its own key (CA or not).
func selfSigned(c *x509.Certificate) bool {
	return string(c.RawIssuer) == string(c.RawSubject) && c.CheckSignature(c.SignatureAlgorithm, c.RawTBSCertificate, c.Signature) == nil
}

func ipStrings(ips []net.IP) []string {
	var out []string
	for _, ip := range ips {
		out = append(out, ip.String())
	}
	return out
}

// sctOID is the certificate extension holding embedded CT timestamps.
var sctOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

// Inspect looks at the TLS certificate a server presents.
func Inspect(ctx context.Context, host string, port int, sni, proto string) CertReport {
	if sni == "" && net.ParseIP(host) == nil {
		sni = host
	}
	r := CertReport{Host: host, Port: port, SNI: sni, StartTLS: proto}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	st, remote, took, err := handshake(ctx, addr, sni, proto, 0, 0)
	r.Addr, r.Handshake = remote, took
	if err != nil {
		r.Error = explainTLS(err, port, proto)
		return r
	}
	r.Version, r.Cipher, r.ALPN = TLSName(st.Version), tls.CipherSuiteName(st.CipherSuite), st.NegotiatedProtocol
	r.OCSP = len(st.OCSPResponse) > 0
	leaf := st.PeerCertificates[0]
	r.CT = len(st.SignedCertificateTimestamps) > 0
	for _, e := range leaf.Extensions {
		r.CT = r.CT || e.Id.Equal(sctOID)
	}
	for _, c := range st.PeerCertificates {
		r.Chain = append(r.Chain, info(c))
	}

	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	verifyName := sni
	if verifyName == "" {
		verifyName = host
	}
	chains, verr := leaf.Verify(x509.VerifyOptions{DNSName: verifyName, Roots: certRoots, Intermediates: inter, CurrentTime: now()})
	r.Trusted = verr == nil
	missing := ""
	if verr == nil && len(chains) > 0 {
		// Some systems (Windows, macOS) fetch a missing intermediate on their
		// own and call the chain fine; most other clients don't.
		for _, c := range chains[0][1 : len(chains[0])-1] {
			sent := false
			for _, p := range st.PeerCertificates {
				sent = sent || c.Equal(p)
			}
			if !sent && missing == "" {
				missing = nameOf(c.Subject)
			}
		}
		root := chains[0][len(chains[0])-1]
		sent := false
		for _, c := range st.PeerCertificates {
			sent = sent || c.Equal(root)
		}
		if !sent {
			ri := info(root)
			ri.FromStore = true
			r.Chain = append(r.Chain, ri)
		}
	}

	// Which versions does it accept? One short handshake each.
	r.Versions = map[string]bool{}
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13} {
		if v == st.Version {
			r.Versions[TLSName(v)] = true
			continue
		}
		_, _, _, err := handshake(ctx, addr, sni, proto, v, v)
		r.Versions[TLSName(v)] = err == nil
	}
	r.Problem, r.Checks = judge(r, leaf, st.PeerCertificates, verr, verifyName, missing)
	return r
}

func explainTLS(err error, port int, proto string) string {
	var op *net.OpError
	var dns *net.DNSError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return dns.Name + " doesn't exist"
	case errors.As(err, &op) && op.Op == "dial" && strings.Contains(err.Error(), "refused"):
		return fmt.Sprintf("nothing listens on port %d", port)
	case errors.As(err, &op) && op.Op == "dial":
		return fmt.Sprintf("no answer on port %d", port)
	case strings.Contains(err.Error(), "first record does not look like a TLS handshake") && proto == "":
		hint := ""
		if p := StartTLSFor(port); p != "" {
			hint = fmt.Sprintf(" (try --starttls %s)", p)
		}
		return fmt.Sprintf("port %d doesn't speak TLS right away%s", port, hint)
	}
	return err.Error()
}

// judge turns what the server showed into findings.
func judge(r CertReport, leaf *x509.Certificate, sent []*x509.Certificate, verr error, name, missing string) (string, []domain.Check) {
	var cs []domain.Check
	add := func(st domain.Status, title, detail, fix string) {
		cs = append(cs, domain.Check{Status: st, Title: title, Detail: detail, Fix: fix})
	}
	problem := ""
	var hn x509.HostnameError
	var ua x509.UnknownAuthorityError
	var inv x509.CertificateInvalidError
	switch {
	case verr == nil && missing != "":
		problem = "incomplete_chain"
		add(domain.Bad, "Incomplete chain", "the server doesn't send the intermediate certificate "+missing+"; this computer fetched it, most clients won't",
			"Configure the full chain (the \"fullchain\" file) on the server. Browsers may cope; apps, scripts and other servers fail.")
	case verr == nil:
		root := r.Chain[len(r.Chain)-1]
		add(domain.OK, "Trusted", "chain ends at "+root.Subject, "")
	case errors.As(verr, &inv) && inv.Reason == x509.Expired:
		problem = "expired"
		if now().Before(leaf.NotBefore) {
			problem = "not_yet_valid"
			add(domain.Bad, "Not valid yet", "valid from "+leaf.NotBefore.UTC().Format("2006-01-02 15:04 UTC"),
				"Check the clock of the machine that issued it, or of this computer.")
		} else {
			add(domain.Bad, "Expired", "on "+leaf.NotAfter.UTC().Format("2006-01-02"), "Renew the certificate; clients refuse it until you do.")
		}
	case errors.As(verr, &hn):
		problem = "name"
		names := strings.Join(r.Chain[0].Names, ", ")
		if names == "" {
			names = r.Chain[0].Subject
		}
		add(domain.Bad, "Wrong name: not valid for "+name, "valid for "+names, "Get a certificate that includes "+name+", or connect with the name it's for.")
	case r.Chain[0].SelfSigned:
		problem = "self_signed"
		add(domain.Bad, "Self-signed", r.Chain[0].Subject, "Use a certificate from a public authority (Let's Encrypt is free); clients don't trust self-signed ones.")
	case errors.As(verr, &ua) && len(sent) == 1 && len(leaf.IssuingCertificateURL) > 0:
		problem = "incomplete_chain"
		add(domain.Bad, "Incomplete chain", "the server sends only its own certificate, not the intermediate one from "+r.Chain[0].Issuer,
			"Configure the full chain (the \"fullchain\" file) on the server. Browsers may cope; apps, scripts and other servers fail.")
	default:
		problem = "untrusted"
		add(domain.Bad, "Not trusted", oneLine(verr.Error()), "Use a certificate from a public authority and serve the full chain.")
	}

	d := r.Chain[0].Days
	until := leaf.NotAfter.UTC().Format("2006-01-02")
	switch {
	case problem == "expired":
	case d < 7:
		add(domain.Bad, fmt.Sprintf("Expires in %d days", d), until, "Renew it now, and check why automatic renewal didn't.")
	case d < 21:
		add(domain.Warn, fmt.Sprintf("Expires in %d days", d), until, "Renew soon; if renewal is automatic, it should have happened by now.")
	default:
		add(domain.OK, fmt.Sprintf("Valid for %d more days", d), "until "+until, "")
	}

	if r.Trusted && leaf.NotAfter.Sub(leaf.NotBefore) > 398*24*time.Hour {
		add(domain.Warn, "Valid for more than 398 days", leaf.NotBefore.Format("2006-01-02")+" to "+until,
			"Browsers reject public certificates that long; issue a shorter one.")
	}
	for i, c := range sent {
		if rk, ok := c.PublicKey.(*rsa.PublicKey); ok && rk.N.BitLen() < 2048 {
			add(domain.Bad, "Weak key: "+r.Chain[i].Key, r.Chain[i].Subject, "Issue a new certificate with an RSA 2048+ or ECDSA P-256 key.")
		}
		if (c.SignatureAlgorithm == x509.SHA1WithRSA || c.SignatureAlgorithm == x509.ECDSAWithSHA1 || c.SignatureAlgorithm == x509.MD5WithRSA) && !r.Chain[i].SelfSigned {
			add(domain.Bad, "Weak signature: "+c.SignatureAlgorithm.String(), r.Chain[i].Subject, "Reissue the certificate; SHA-1 signatures aren't trusted any more.")
		}
	}
	if len(sent) > 1 && sent[len(sent)-1].IsCA && r.Chain[len(sent)-1].SelfSigned {
		add(domain.Info, "Sends the root certificate too", r.Chain[len(sent)-1].Subject, "Clients have it already; leaving it out saves a little on every handshake.")
	}

	var old []string
	for _, v := range []string{"TLS 1.0", "TLS 1.1"} {
		if r.Versions[v] {
			old = append(old, v)
		}
	}
	switch {
	case len(old) > 0 && !r.Versions["TLS 1.2"] && !r.Versions["TLS 1.3"]:
		add(domain.Bad, "Only "+strings.Join(old, " and "), "current browsers and most apps refuse to connect", "Turn on TLS 1.2 and 1.3 on the server (and turn the old versions off).")
	case len(old) > 0:
		add(domain.Warn, "Accepts "+strings.Join(old, " and "), "deprecated since 2021 (RFC 8996)", "Turn off TLS 1.0 and 1.1 on the server; keep 1.2 and 1.3.")
	}
	if !r.Versions["TLS 1.3"] && (r.Versions["TLS 1.2"] || len(old) == 0) {
		add(domain.Info, "No TLS 1.3", "it's faster and safer; most servers support it now", "Turn TLS 1.3 on if the server software allows it.")
	}
	if r.Trusted && !r.CT && r.StartTLS == "" {
		add(domain.Warn, "Not in Certificate Transparency logs", "browsers expect public certificates to be logged", "Reissue it from a public authority; they log certificates automatically.")
	}
	return problem, cs
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}
