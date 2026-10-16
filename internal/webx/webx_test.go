package webx

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- HTTP ---

func testServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test")
		w.Write([]byte(strings.Repeat("x", 1000)))
	})
	mux.HandleFunc("/r1", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/r2", 301) })
	mux.HandleFunc("/r2", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", 302) })
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop2", 302) })
	mux.HandleFunc("/loop2", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/loop", 302) })
	mux.HandleFunc("/keep", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/echo", 307) })
	mux.HandleFunc("/see", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/echo", 303) })
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Method", r.Method)
		w.Header().Set("X-Body", string(b))
		w.Header().Set("X-UA", r.UserAgent())
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(60 * time.Millisecond)
		w.WriteHeader(503)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func trusting(srv *httptest.Server) Options {
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return Options{UserAgent: "netcheck/test", tlsConfig: &tls.Config{RootCAs: pool}}
}

func TestFetch(t *testing.T) {
	srv := testServer(t)
	o := trusting(srv)
	r := Fetch(context.Background(), srv.URL+"/", o)
	f := r.Final()
	if r.Error != "" || f.Status != 200 || f.Size != 1000 || f.Proto != "HTTP/2.0" || f.TLSVersion != "TLS 1.3" || f.Header.Get("Server") != "test" {
		t.Fatalf("got %+v", r)
	}
	if f.Phases.Total <= 0 || f.Phases.Total < f.Phases.Wait {
		t.Errorf("phases %+v", f.Phases)
	}
	if r := Fetch(context.Background(), srv.URL+"/slow", o); r.Final().Status != 503 || r.Final().Phases.Wait < 50*time.Millisecond {
		t.Errorf("slow: %+v", r.Final())
	}
	o.HTTP1 = true
	if r := Fetch(context.Background(), srv.URL+"/", o); r.Final().Proto != "HTTP/1.1" {
		t.Errorf("--http1: %s", r.Final().Proto)
	}
}

func TestFetchRedirects(t *testing.T) {
	srv := testServer(t)
	o := trusting(srv)
	r := Fetch(context.Background(), srv.URL+"/r1", o)
	if len(r.Hops) != 3 || r.Hops[0].Status != 301 || r.Hops[1].Status != 302 || r.Final().Status != 200 || r.Error != "" {
		t.Errorf("chain: %+v", r.Hops)
	}
	o.NoFollow = true
	if r := Fetch(context.Background(), srv.URL+"/r1", o); len(r.Hops) != 1 || r.Final().Status != 301 {
		t.Errorf("--no-follow: %+v", r.Hops)
	}
	o.NoFollow = false
	if r := Fetch(context.Background(), srv.URL+"/loop", o); !strings.Contains(r.Error, "loop") {
		t.Errorf("loop: %q", r.Error)
	}
	o.Body = "hello"
	r = Fetch(context.Background(), srv.URL+"/keep", o)
	if h := r.Final().Header; h.Get("X-Method") != "POST" || h.Get("X-Body") != "hello" || h.Get("X-UA") != "netcheck/test" {
		t.Errorf("307 keeps the POST: %v", h)
	}
	if h := Fetch(context.Background(), srv.URL+"/see", o).Final().Header; h.Get("X-Method") != "GET" || h.Get("X-Body") != "" {
		t.Errorf("303 turns it into a GET: %v", h)
	}
}

func TestFetchErrors(t *testing.T) {
	srv := testServer(t)
	if r := Fetch(context.Background(), srv.URL+"/", Options{}); !strings.Contains(r.Error, "isn't trusted") {
		t.Errorf("untrusted: %q", r.Error)
	}
	if r := Fetch(context.Background(), srv.URL+"/", Options{Insecure: true}); r.Error != "" {
		t.Errorf("-k: %q", r.Error)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	if r := Fetch(context.Background(), "https://"+addr+"/", Options{}); r.Error != "connection refused" {
		t.Errorf("refused: %q", r.Error)
	}
	if _, err := NormalizeURL("ftp://x"); err == nil {
		t.Error("ftp isn't http")
	}
	if u, _ := NormalizeURL("example.com"); u.String() != "https://example.com/" {
		t.Errorf("bare host: %s", u)
	}
}

// --- certificates ---

type pki struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func issue(t *testing.T, parent *pki, cn string, ca bool, notAfter time.Time, names ...string) *pki {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"Test"}}, DNSNames: names,
		NotBefore: time.Now().Add(-48 * time.Hour), NotAfter: notAfter, IsCA: ca, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if !ca {
		// Public certificates carry their CT log stamps; a dummy one will do.
		tmpl.ExtraExtensions = []pkix.Extension{{Id: sctOID, Value: []byte{0x04, 0x02, 0x00, 0x00}}}
	}
	signer, signKey := tmpl, key
	if parent != nil {
		signer, signKey = parent.cert, parent.key
		tmpl.IssuingCertificateURL = []string{"http://127.0.0.1:1/ca.crt"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &pki{c, key, der}
}

type certServer struct {
	chain    []*pki
	min, max uint16
	smtp     bool // speak SMTP up to STARTTLS first
	plain    bool // never start TLS
}

// serve runs a local TLS server and points dialCert at it.
func serve(t *testing.T, s certServer, roots *x509.CertPool) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{PrivateKey: s.chain[0].key}
	for _, c := range s.chain {
		cert.Certificate = append(cert.Certificate, c.der)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: s.min, MaxVersion: s.max}
	if s.min != 0 && s.min < tls.VersionTLS12 {
		for _, c := range append(tls.CipherSuites(), tls.InsecureCipherSuites()...) {
			cfg.CipherSuites = append(cfg.CipherSuites, c.ID)
		}
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				if s.smtp || s.plain {
					fmt.Fprint(c, "220 mx.test ESMTP\r\n")
					if s.plain {
						time.Sleep(time.Second)
						return
					}
					r := bufio.NewReader(c)
					r.ReadString('\n') // EHLO
					fmt.Fprint(c, "250-mx.test\r\n250 STARTTLS\r\n")
					r.ReadString('\n') // STARTTLS
					fmt.Fprint(c, "220 go ahead\r\n")
				}
				tc := tls.Server(c, cfg)
				tc.Handshake()
				io.Copy(io.Discard, tc)
			}()
		}
	}()
	oldDial, oldRoots := dialCert, certRoots
	dialCert = func(ctx context.Context, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", l.Addr().String())
	}
	certRoots = roots
	t.Cleanup(func() { l.Close(); dialCert, certRoots = oldDial, oldRoots })
}

func has(r CertReport, title string) bool {
	for _, c := range r.Checks {
		if strings.Contains(c.Title, title) {
			return true
		}
	}
	return false
}

func TestInspect(t *testing.T) {
	year := time.Now().Add(200 * 24 * time.Hour)
	root := issue(t, nil, "Test Root", true, year.Add(1000*24*time.Hour))
	inter := issue(t, root, "Test Intermediate", true, year.Add(500*24*time.Hour))
	leaf := issue(t, inter, "site.test", false, year, "site.test", "www.site.test")
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)

	serve(t, certServer{chain: []*pki{leaf, inter}}, roots)
	r := Inspect(context.Background(), "site.test", 443, "", "")
	if r.Error != "" || !r.Trusted || r.Problem != "" || len(r.Chain) != 3 || !r.Chain[2].FromStore || r.Chain[0].Key != "ECDSA P-256" {
		t.Fatalf("good chain: %+v", r)
	}
	if !r.Versions["TLS 1.3"] || r.Versions["TLS 1.0"] || !has(r, "Trusted") || !has(r, "Valid for") {
		t.Errorf("versions %v, checks %+v", r.Versions, r.Checks)
	}

	cases := []struct {
		name    string
		srv     certServer
		host    string
		problem string
		title   string
	}{
		{"leaf only", certServer{chain: []*pki{leaf}}, "site.test", "incomplete_chain", "Incomplete chain"},
		{"wrong name", certServer{chain: []*pki{leaf, inter}}, "other.test", "name", "Wrong name"},
		{"self-signed", certServer{chain: []*pki{issue(t, nil, "self.test", false, year, "self.test")}}, "self.test", "self_signed", "Self-signed"},
		{"expired", certServer{chain: []*pki{issue(t, inter, "old.test", false, time.Now().Add(-time.Hour), "old.test"), inter}}, "old.test", "expired", "Expired"},
		{"expiring", certServer{chain: []*pki{issue(t, inter, "soon.test", false, time.Now().Add(3*24*time.Hour), "soon.test"), inter}}, "soon.test", "", "Expires in 2 days"},
		{"old TLS", certServer{chain: []*pki{leaf, inter}, min: tls.VersionTLS10, max: tls.VersionTLS12}, "site.test", "", "Accepts TLS 1.0 and TLS 1.1"},
		{"only old TLS", certServer{chain: []*pki{leaf, inter}, min: tls.VersionTLS10, max: tls.VersionTLS10}, "site.test", "", "Only TLS 1.0"},
	}
	for _, c := range cases {
		serve(t, c.srv, roots)
		r := Inspect(context.Background(), c.host, 443, "", "")
		if r.Error != "" || r.Problem != c.problem || !has(r, c.title) {
			var titles []string
			for _, x := range r.Checks {
				titles = append(titles, string(x.Status)+" "+x.Title)
			}
			t.Errorf("%s: problem %q error %q checks %v", c.name, r.Problem, r.Error, titles)
		}
	}

	serve(t, certServer{chain: []*pki{leaf, inter}, max: tls.VersionTLS12}, roots)
	if r := Inspect(context.Background(), "site.test", 443, "", ""); !has(r, "No TLS 1.3") || r.Version != "TLS 1.2" {
		t.Errorf("no 1.3: %+v", r.Checks)
	}
}

func TestInspectStartTLS(t *testing.T) {
	year := time.Now().Add(200 * 24 * time.Hour)
	root := issue(t, nil, "Test Root", true, year)
	leaf := issue(t, root, "mx.test", false, year, "mx.test")
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	serve(t, certServer{chain: []*pki{leaf}, smtp: true}, roots)
	r := Inspect(context.Background(), "mx.test", 25, "", "smtp")
	if r.Error != "" || !r.Trusted || r.StartTLS != "smtp" || r.ALPN != "" {
		t.Errorf("smtp STARTTLS: %+v", r)
	}
	serve(t, certServer{chain: []*pki{leaf}, plain: true}, roots)
	if r := Inspect(context.Background(), "mx.test", 25, "", ""); !strings.Contains(r.Error, "--starttls smtp") {
		t.Errorf("plain port hint: %q", r.Error)
	}
	if StartTLSFor(587) != "smtp" || StartTLSFor(143) != "imap" || StartTLSFor(443) != "" {
		t.Error("ports")
	}
}
