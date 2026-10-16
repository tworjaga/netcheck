package domain

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"strings"
	"syscall"
	"time"
)

// SMTPServer is what one mail server showed on port 25.
type SMTPServer struct {
	Host        string  `json:"host"`
	Addr        string  `json:"addr"`
	Banner      string  `json:"banner,omitempty"`
	PTR         string  `json:"ptr,omitempty"`
	PTRMatches  bool    `json:"ptr_confirmed"` // the PTR name resolves back to the address
	STARTTLS    bool    `json:"starttls"`
	TLSVersion  string  `json:"tls_version,omitempty"`
	CertIssuer  string  `json:"cert_issuer,omitempty"`
	CertDays    int     `json:"cert_days,omitempty"`
	CertProblem string  `json:"cert_problem,omitempty"` // "", "name", "untrusted", "expired"
	ConnectMs   float64 `json:"connect_ms,omitempty"`
	Blocked     bool    `json:"blocked,omitempty"` // no answer at all: likely port 25 blocked on the way out
	Error       string  `json:"error,omitempty"`
}

// Test seams: opening the connection, and the roots a certificate is
// checked against (nil = the system's).
var (
	dialSMTP = func(ctx context.Context, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 8 * time.Second}
		return d.DialContext(ctx, "tcp", addr)
	}
	smtpRoots *x509.CertPool
)

// heloName is what to introduce ourselves as: our address in brackets,
// which RFC 5321 allows when there's no name to give.
func heloName(c net.Conn) string {
	if h, _, err := net.SplitHostPort(c.LocalAddr().String()); err == nil && net.ParseIP(h) != nil {
		return "[" + h + "]"
	}
	return "localhost"
}

// probeSMTP talks to a mail server as far as the TLS handshake and leaves:
// greeting, EHLO, STARTTLS, certificate, QUIT. It never sends MAIL FROM, so
// no mail is ever sent.
func probeSMTP(ctx context.Context, host, addr string) SMTPServer {
	s := SMTPServer{Host: host, Addr: addr}
	start := now()
	conn, err := dialSMTP(ctx, net.JoinHostPort(addr, "25"))
	if err != nil {
		var ne net.Error
		switch {
		case errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "refused"):
			s.Error = "refused connections on port 25"
		case errors.As(err, &ne) && ne.Timeout(), errors.Is(err, os.ErrDeadlineExceeded):
			s.Blocked, s.Error = true, "no answer on port 25"
		default:
			s.Error = err.Error()
		}
		return s
	}
	defer conn.Close()
	s.ConnectMs = float64(now().Sub(start).Microseconds()) / 1000
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	tp := textproto.NewConn(conn)

	_, msg, err := tp.ReadResponse(220)
	if err != nil {
		s.Error = "bad greeting: " + oneLine(err.Error())
		return s
	}
	s.Banner = oneLine(strings.SplitN(msg, "\n", 2)[0])

	id, err := tp.Cmd("EHLO %s", heloName(conn))
	if err != nil {
		s.Error = err.Error()
		return s
	}
	tp.StartResponse(id)
	_, ext, err := tp.ReadResponse(250)
	tp.EndResponse(id)
	if err != nil {
		s.Error = "refused EHLO: " + oneLine(err.Error())
		return s
	}
	for _, l := range strings.Split(ext, "\n") {
		if strings.EqualFold(strings.TrimSpace(l), "STARTTLS") {
			s.STARTTLS = true
		}
	}
	if !s.STARTTLS {
		tp.Cmd("QUIT")
		return s
	}
	id, _ = tp.Cmd("STARTTLS")
	tp.StartResponse(id)
	_, _, err = tp.ReadResponse(220)
	tp.EndResponse(id)
	if err != nil {
		s.Error = "offered STARTTLS but refused it: " + oneLine(err.Error())
		return s
	}
	// Look at whatever certificate comes, then judge it ourselves.
	tc := tls.Client(conn, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err := tc.HandshakeContext(ctx); err != nil {
		s.Error = "TLS handshake failed: " + oneLine(err.Error())
		return s
	}
	st := tc.ConnectionState()
	s.TLSVersion = tlsNames[st.Version]
	if s.TLSVersion == "" {
		s.TLSVersion = fmt.Sprintf("TLS 0x%04x", st.Version)
	}
	leaf := st.PeerCertificates[0]
	s.CertIssuer = issuer(leaf)
	s.CertDays = int(leaf.NotAfter.Sub(now()).Hours() / 24)
	inter := x509.NewCertPool()
	for _, c := range st.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	_, verr := leaf.Verify(x509.VerifyOptions{DNSName: host, Roots: smtpRoots, Intermediates: inter, CurrentTime: now()})
	var name x509.HostnameError
	var invalid x509.CertificateInvalidError
	switch {
	case verr == nil:
	case errors.As(verr, &name):
		s.CertProblem = "name"
	case errors.As(verr, &invalid) && invalid.Reason == x509.Expired:
		s.CertProblem = "expired"
	default:
		s.CertProblem = "untrusted"
	}
	tc.Write([]byte("QUIT\r\n"))
	return s
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 120 {
		s = s[:117] + "..."
	}
	return s
}
