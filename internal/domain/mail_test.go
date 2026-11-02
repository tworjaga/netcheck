package domain

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// testCert is a self-signed certificate for names, valid until notAfter.
func testCert(t *testing.T, notAfter time.Time, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: fixedNow.Add(-24 * time.Hour), NotAfter: notAfter, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	tmpl.Issuer.Organization = []string{"Test CA"}
	tmpl.Subject.Organization = []string{"Test CA"}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// smtpFake is a scripted mail server on the far end of a pipe.
type smtpFake struct {
	noTLS    bool
	cert     tls.Certificate
	mailFrom atomic.Bool // set if a client ever starts a message
}

func (f *smtpFake) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	say := func(s string) { fmt.Fprint(c, s) }
	say("220 mx.example.com ESMTP Postfix\r\n")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimSpace(line))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if f.noTLS {
				say("250-mx.example.com\r\n250 SIZE 10240000\r\n")
			} else {
				say("250-mx.example.com\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n")
			}
		case cmd == "STARTTLS":
			say("220 2.0.0 Ready to start TLS\r\n")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if tc.Handshake() != nil {
				return
			}
			tr := bufio.NewReader(tc)
			for {
				l, err := tr.ReadString('\n')
				if err != nil {
					return
				}
				if strings.HasPrefix(strings.ToUpper(l), "MAIL") {
					f.mailFrom.Store(true)
				}
				if strings.HasPrefix(strings.ToUpper(l), "QUIT") {
					return
				}
			}
		case strings.HasPrefix(cmd, "MAIL"):
			f.mailFrom.Store(true)
		case cmd == "QUIT":
			say("221 bye\r\n")
			return
		}
	}
}

func useSMTP(t *testing.T, servers map[string]*smtpFake, roots *x509.CertPool) {
	t.Helper()
	oldDial, oldRoots := dialSMTP, smtpRoots
	smtpRoots = roots
	dialSMTP = func(_ context.Context, addr string) (net.Conn, error) {
		host, _, _ := net.SplitHostPort(addr)
		f, ok := servers[host]
		if !ok {
			return nil, fmt.Errorf("dial tcp %s: i/o timeout: %w", addr, os.ErrDeadlineExceeded)
		}
		client, server := net.Pipe()
		go f.serve(server)
		return client, nil
	}
	t.Cleanup(func() { dialSMTP, smtpRoots = oldDial, oldRoots })
}

func TestProbeSMTP(t *testing.T) {
	cert, roots := testCert(t, fixedNow.Add(60*24*time.Hour), "mail.example.com")
	good := &smtpFake{cert: cert}
	plain := &smtpFake{noTLS: true}
	useSMTP(t, map[string]*smtpFake{"192.0.2.25": good, "192.0.2.26": plain}, roots)
	old := now
	now = func() time.Time { return fixedNow }
	defer func() { now = old }()

	s := probeSMTP(context.Background(), "mail.example.com", "192.0.2.25")
	if s.Error != "" || !s.STARTTLS || s.TLSVersion != "TLS 1.3" || s.CertProblem != "" || s.CertDays != 60 || s.CertIssuer != "Test CA" {
		t.Errorf("good server: %+v", s)
	}
	if s.Banner != "mx.example.com ESMTP Postfix" {
		t.Errorf("banner %q", s.Banner)
	}
	if s := probeSMTP(context.Background(), "other.example.net", "192.0.2.25"); s.CertProblem != "name" {
		t.Errorf("name mismatch: %+v", s)
	}
	if s := probeSMTP(context.Background(), "mail.example.com", "192.0.2.26"); s.STARTTLS || s.Error != "" {
		t.Errorf("no STARTTLS: %+v", s)
	}
	if s := probeSMTP(context.Background(), "mail.example.com", "192.0.2.99"); !s.Blocked {
		t.Errorf("no answer is blocked: %+v", s)
	}
	if good.mailFrom.Load() || plain.mailFrom.Load() {
		t.Error("the probe must never start a message")
	}
}

func TestServerChecks(t *testing.T) {
	ok := SMTPServer{Host: "mx.example.com", Addr: "192.0.2.25", Banner: "mx ESMTP", STARTTLS: true, TLSVersion: "TLS 1.3", CertDays: 60, PTR: "mx.example.com", PTRMatches: true}
	if cs := serverChecks([]SMTPServer{ok}, false); len(cs) != 1 || cs[0].Status != OK {
		t.Errorf("healthy: %+v", cs)
	}
	blocked := SMTPServer{Host: "mx.example.com", Blocked: true}
	if cs := serverChecks([]SMTPServer{blocked, blocked}, false); len(cs) != 1 || cs[0].Status != Info || !strings.Contains(cs[0].Title, "blocked") {
		t.Errorf("all blocked is about this network: %+v", cs)
	}
	if cs := serverChecks([]SMTPServer{ok, blocked}, false); cs[len(cs)-1].Status != Warn {
		t.Errorf("one blocked of two is that server: %+v", cs)
	}
	cases := []struct {
		edit    func(s *SMTPServer)
		enforce bool
		title   string
		st      Status
	}{
		{func(s *SMTPServer) { s.STARTTLS = false }, false, "no STARTTLS", Bad},
		{func(s *SMTPServer) { s.CertProblem = "name" }, false, "another name", Warn},
		{func(s *SMTPServer) { s.CertProblem = "name" }, true, "another name", Bad},
		{func(s *SMTPServer) { s.CertDays = -2; s.CertProblem = "expired" }, false, "expired", Bad},
		{func(s *SMTPServer) { s.CertDays = 5 }, false, "expires in 5 days", Warn},
		{func(s *SMTPServer) { s.PTR = "" }, false, "no reverse DNS", Warn},
		{func(s *SMTPServer) { s.PTRMatches = false }, false, "doesn't resolve back", Warn},
	}
	for _, c := range cases {
		s := ok
		c.edit(&s)
		found := false
		for _, x := range serverChecks([]SMTPServer{s}, c.enforce) {
			if strings.Contains(x.Title, c.title) {
				found = true
				if x.Status != c.st || x.Fix == "" {
					t.Errorf("%s: %s, fix %q", c.title, x.Status, x.Fix)
				}
			}
		}
		if !found {
			t.Errorf("missing %q", c.title)
		}
	}
}

func spfNet(recs map[string][]string) *fakeNet {
	m := map[string]*dnsx.Msg{}
	for name, vals := range recs {
		var ans []dnsx.RR
		for _, v := range vals {
			ans = append(ans, rr(name, dnsx.TypeTXT, `"`+v+`"`, nil))
		}
		m[resolver+" "+name+" TXT"] = &dnsx.Msg{Answer: ans}
	}
	return &fakeNet{msgs: m, down: map[string]bool{}}
}

func TestCountSPF(t *testing.T) {
	f := spfNet(map[string][]string{
		"example.com.":      {"v=spf1 mx a:web.example.com include:_spf.a.test include:missing.test ip4:192.0.2.0/24 -all"},
		"_spf.a.test.":      {"v=spf1 include:_spf.b.test exists:%{i}.x.test ~all"},
		"_spf.b.test.":      {"v=spf1 ip4:198.51.100.0/24 -all"},
		"loop.example.":     {"v=spf1 include:loop.example -all"},
		"twice.example.":    {"v=spf1 include:dup.test -all"},
		"dup.test.":         {"v=spf1 -all", "v=spf1 ~all"},
		"big.example.":      {"v=spf1 " + strings.Repeat("a ", 11) + "-all"},
		"redirect.example.": {"v=spf1 redirect=_spf.a.test"},
	})
	useNet(t, f, nil, nil)
	c := countSPF(context.Background(), "example.com.")
	// mx, a, include a (+ include b + exists), include missing = 6
	if c.Lookups != 6 || c.Void != 1 || len(c.Missing) != 1 || c.Missing[0] != "missing.test" || c.Includes["include:_spf.a.test"] != 3 {
		t.Errorf("count: %+v", c)
	}
	if cs := spfCountChecks(c); cs[0].Status != OK || cs[1].Status != Warn {
		t.Errorf("checks: %+v", cs)
	}
	if c := countSPF(context.Background(), "loop.example."); !c.Loop {
		t.Errorf("loop: %+v", c)
	}
	if c := countSPF(context.Background(), "twice.example."); len(c.Multiple) != 1 {
		t.Errorf("multiple: %+v", c)
	}
	if c := countSPF(context.Background(), "big.example."); c.Lookups != 11 || spfCountChecks(c)[0].Status != Bad {
		t.Errorf("over the limit: %+v", c)
	}
	if c := countSPF(context.Background(), "redirect.example."); c.Lookups != 3 || c.Includes["redirect:_spf.a.test"] != 3 {
		t.Errorf("redirect: %+v", c)
	}
}

func TestMTASTS(t *testing.T) {
	if !stsMatches("*.mx.example.com", "a.mx.example.com.") || stsMatches("*.example.com", "a.b.example.com") || !stsMatches("MX.example.com", "mx.example.com") {
		t.Error("patterns")
	}
	mx := []MXHost{{Host: "mx1.example.com"}, {Host: "mx2.example.com"}}
	f := spfNet(map[string][]string{"_mta-sts.example.com.": {"v=STSv1; id=20261014"}, "_smtp._tls.example.com.": {"v=TLSRPTv1; rua=mailto:tls@example.com"}})
	useNet(t, f, nil, nil)
	policy := "version: STSv1\nmode: enforce\nmx: *.example.com\nmax_age: 604800\n"
	old := fetchPolicy
	defer func() { fetchPolicy = old }()
	fetchPolicy = func(_ context.Context, url string) (string, error) {
		if url != "https://mta-sts.example.com/.well-known/mta-sts.txt" {
			t.Errorf("url %s", url)
		}
		return policy, nil
	}
	p, cs := mtaSTS(context.Background(), "example.com.", mx)
	if p == nil || p.ID != "20261014" || p.Mode != "enforce" || cs[0].Status != OK || cs[1].Status != OK {
		t.Errorf("enforced: %+v %+v", p, cs)
	}
	policy = "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 604800\n"
	if _, cs := mtaSTS(context.Background(), "example.com.", mx); cs[0].Status != Bad || !strings.Contains(cs[0].Detail, "mx2.example.com") {
		t.Errorf("uncovered MX under enforce: %+v", cs)
	}
	fetchPolicy = func(context.Context, string) (string, error) { return "", errors.New("x509: certificate has expired") }
	if _, cs := mtaSTS(context.Background(), "example.com.", mx); cs[0].Status != Bad {
		t.Errorf("unfetchable: %+v", cs)
	}
	useNet(t, spfNet(nil), nil, nil)
	if _, cs := mtaSTS(context.Background(), "example.com.", mx); len(cs) != 1 || cs[0].Status != Info {
		t.Errorf("none: %+v", cs)
	}
}

func TestMailAudit(t *testing.T) {
	f := healthy()
	f.msgs[resolver+" _mta-sts.example.com. TXT"] = &dnsx.Msg{Answer: []dnsx.RR{rr("x", dnsx.TypeTXT, `"v=STSv1; id=1"`, nil)}}
	f.msgs[resolver+" _smtp._tls.example.com. TXT"] = &dnsx.Msg{Answer: []dnsx.RR{rr("x", dnsx.TypeTXT, `"v=TLSRPTv1; rua=mailto:t@example.com"`, nil)}}
	f.msgs[resolver+" "+dnsx.ReverseName(net.ParseIP(mxAddr))+" PTR"] = &dnsx.Msg{Answer: []dnsx.RR{rr("x", dnsx.TypePTR, "mail.example.com.", nil)}}
	useNet(t, f, nil, nil)
	cert, roots := testCert(t, fixedNow.Add(60*24*time.Hour), "mail.example.com")
	server := &smtpFake{cert: cert}
	useSMTP(t, map[string]*smtpFake{mxAddr: server}, roots)
	old := fetchPolicy
	defer func() { fetchPolicy = old }()
	fetchPolicy = func(context.Context, string) (string, error) {
		return "version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n", nil
	}
	r := MailAudit(context.Background(), "example.com")
	_, warn, bad := r.Count()
	if r.Error != "" || warn+bad != 0 || r.Grade != "A+" || len(r.Servers) != 1 || !r.Servers[0].PTRMatches || r.SPF.Lookups != 1 {
		for _, c := range r.Checks {
			t.Logf("%s %s: %s (%s)", c.Status, c.Area, c.Title, c.Detail)
		}
		t.Fatalf("grade %s, servers %+v", r.Grade, r.Servers)
	}
	for _, area := range []string{AreaRecords, AreaSPF, AreaServers, AreaSTS, AreaBL} {
		if find(Report{Checks: r.Checks}, area, "") == nil {
			t.Errorf("no %s checks", area)
		}
	}
	if server.mailFrom.Load() {
		t.Error("no message started")
	}
	f.msgs[resolver+" nope.example. MX"] = &dnsx.Msg{Rcode: dnsx.RcodeNXDomain}
	if r := MailAudit(context.Background(), "nope.example"); r.Error != "nope.example doesn't exist" {
		t.Errorf("missing: %q", r.Error)
	}
}
