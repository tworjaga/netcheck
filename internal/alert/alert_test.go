package alert

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"testing"
	"time"
)

var ev = Event{Time: time.Date(2026, 10, 15, 14, 2, 0, 0, time.UTC), Kind: "down", Target: "https://shop.test", Name: "Shop", Text: "Shop is down: 503", Detail: "503", Host: "watcher"}

func TestParse(t *testing.T) {
	t.Setenv("NETCHECK_SMTP_PASSWORD", "secret")
	good := map[string]string{
		"desktop":                          "desktop notification",
		"webhook https://ntfy.sh/my-topic": "webhook ntfy.sh",
		"command notify.sh --loud":         "command",
		"email me@x.test smtp=smtp.x.test:587 user=me@x.test": "email to me@x.test",
	}
	for spec, name := range good {
		c, err := Parse(spec)
		if err != nil || c.Name() != name {
			t.Errorf("%q: %v %v", spec, c, err)
		}
	}
	if m, _ := Parse("email me@x.test smtp=smtp.x.test:587 user=me@x.test"); m.(Email).Password != "secret" {
		t.Error("the password comes from the environment")
	}
	for _, bad := range []string{"", "pager", "webhook", "webhook ftp://x", "command", "email", "email nobody", "email me@x.test", "email me@x.test smtp=nohost",
		"email me@x.test smtp=s:587 password=hunter2", "email me@x.test smtp=s:587 colour=red"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
	t.Setenv("NETCHECK_SMTP_PASSWORD", "")
	if _, err := Parse("email me@x.test smtp=s:587 user=me"); err == nil || !strings.Contains(err.Error(), "NETCHECK_SMTP_PASSWORD") {
		t.Errorf("no password: %v", err)
	}
}

func TestWebhookFormats(t *testing.T) {
	type got struct {
		body    string
		ctype   string
		headers http.Header
	}
	hits := make(chan got, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		hits <- got{string(b), r.Header.Get("Content-Type"), r.Header}
		if strings.Contains(r.URL.Path, "broken") {
			http.Error(w, "nope", 400)
		}
	}))
	defer srv.Close()
	for _, c := range []struct{ url, kind string }{
		{"https://discord.com/api/webhooks/1/abc", "discord"}, {"https://hooks.slack.com/services/x", "slack"},
		{"https://acme.webhook.office.com/x", "teams"}, {"https://ntfy.sh/topic", "ntfy"}, {"https://ntfy.example.org/t", "ntfy"}, {"https://my.test/hook", "json"},
	} {
		if k := webhookKind(c.url); k != c.kind {
			t.Errorf("%s: %s", c.url, k)
		}
	}
	// Each format, sent to the test server.
	for kind, check := range map[string]func(g got) bool{
		"discord": func(g got) bool { return strings.Contains(g.body, `"content":"DOWN: Shop: Shop is down: 503"`) },
		"slack":   func(g got) bool { return g.body == `{"text":"DOWN: Shop: Shop is down: 503"}` },
		"ntfy": func(g got) bool {
			return g.body == "Shop is down: 503" && g.headers.Get("Title") == "DOWN: Shop" && g.headers.Get("Priority") == "high"
		},
		"json": func(g got) bool {
			var m map[string]any
			return json.Unmarshal([]byte(g.body), &m) == nil && m["text"] == "DOWN: Shop: Shop is down: 503" && m["event"].(map[string]any)["kind"] == "down"
		},
	} {
		req, _ := webhookRequest(context.Background(), map[string]string{"discord": "https://discord.com/api/webhooks/1/x", "slack": "https://hooks.slack.com/x", "ntfy": "https://ntfy.sh/t", "json": "https://my.test/h"}[kind], ev)
		req.URL, _ = req.URL.Parse(srv.URL + "/" + kind)
		req.Host = ""
		if _, err := srv.Client().Do(req); err != nil {
			t.Fatal(err)
		}
		if g := <-hits; !check(g) {
			t.Errorf("%s: %q %q %v", kind, g.body, g.ctype, g.headers)
		}
	}
	if err := (Webhook{URL: srv.URL + "/ok"}).Send(context.Background(), ev); err != nil {
		t.Errorf("send: %v", err)
	}
	<-hits
	if err := (Webhook{URL: srv.URL + "/broken"}).Send(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "400") {
		t.Errorf("a refused webhook: %v", err)
	}
	<-hits
}

func TestCommandAndDesktop(t *testing.T) {
	old := runCmd
	defer func() { runCmd = old }()
	var gotEnv, gotArgs []string
	runCmd = func(_ context.Context, env []string, name string, args ...string) error {
		gotEnv, gotArgs = env, append([]string{name}, args...)
		return nil
	}
	e := ev
	e.Kind, e.DownFor, e.Text = "up", 90*time.Second, "Shop is back up after 1m30s"
	if err := (Command{Line: "notify.sh"}).Send(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	env := strings.Join(gotEnv, "\n")
	for _, want := range []string{"NETCHECK_EVENT=up", "NETCHECK_NAME=Shop", "NETCHECK_TARGET=https://shop.test", "NETCHECK_DOWN_FOR=90", "NETCHECK_HOST=watcher"} {
		if !strings.Contains(env, want) {
			t.Errorf("missing %s in\n%s", want, env)
		}
	}
	if last := gotArgs[len(gotArgs)-1]; last != "notify.sh" {
		t.Errorf("the line goes to the shell whole: %v", gotArgs)
	}
	if err := (Desktop{}).Send(context.Background(), ev); err != nil && runtime.GOOS != "linux" {
		t.Fatal(err)
	}
	switch runtime.GOOS {
	case "windows":
		// The text travels in the environment, never inside the script.
		if gotArgs[0] != "powershell.exe" || !strings.Contains(strings.Join(gotEnv, "\n"), "NETCHECK_TITLE=DOWN: Shop") || strings.Contains(strings.Join(gotArgs, " "), "Shop") {
			t.Errorf("windows: %v %v", gotArgs, gotEnv)
		}
	case "darwin":
		if gotArgs[0] != "osascript" || gotArgs[len(gotArgs)-2] != "DOWN: Shop" {
			t.Errorf("mac: %v", gotArgs)
		}
	}
}

// fakeSMTP is a mail server that speaks STARTTLS and AUTH PLAIN and keeps
// what it was given.
type fakeSMTP struct {
	noTLS bool
	cert  tls.Certificate
	got   chan string
}

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	var r *bufio.Reader = bufio.NewReader(c)
	var w io.Writer = c
	say := func(s string) { fmt.Fprint(w, s+"\r\n") }
	say("220 mail.test ESMTP")
	var log strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			f.got <- log.String()
			return
		}
		cmd := strings.TrimSpace(line)
		log.WriteString(cmd + "\n")
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			if f.noTLS {
				say("250-mail.test\r\n250 AUTH PLAIN")
			} else {
				say("250-mail.test\r\n250-STARTTLS\r\n250 AUTH PLAIN")
			}
		case cmd == "STARTTLS":
			say("220 go ahead")
			tc := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{f.cert}})
			if tc.Handshake() != nil {
				return
			}
			r, w = bufio.NewReader(tc), tc
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			say("235 ok")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RCPT"):
			say("250 ok")
		case cmd == "DATA":
			say("354 go")
			for {
				l, _ := r.ReadString('\n')
				log.WriteString(l)
				if l == ".\r\n" {
					break
				}
			}
			say("250 queued")
		case cmd == "QUIT":
			say("221 bye")
			f.got <- log.String()
			return
		}
	}
}

func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "mail.test"}, DNSNames: []string{"mail.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestEmail(t *testing.T) {
	cert, pool := testCert(t)
	oldDial, oldTLS := dialSMTP, smtpTLSConfig
	defer func() { dialSMTP, smtpTLSConfig = oldDial, oldTLS }()
	smtpTLSConfig = func(host string) *tls.Config { return &tls.Config{ServerName: host, RootCAs: pool} }
	f := &fakeSMTP{cert: cert, got: make(chan string, 1)}
	dialSMTP = func(context.Context, string, bool, string) (net.Conn, error) {
		a, b := net.Pipe()
		go f.serve(b)
		return a, nil
	}
	m := Email{To: "ops@x.test, me@x.test", User: "bot@x.test", Password: "pw", Server: "mail.test:587"}
	if err := m.Send(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	log := <-f.got
	auth := base64.StdEncoding.EncodeToString([]byte("\x00bot@x.test\x00pw"))
	for _, want := range []string{"STARTTLS", "AUTH PLAIN " + auth, "MAIL FROM:<bot@x.test>", "RCPT TO:<ops@x.test>", "RCPT TO:<me@x.test>", "Subject: [netcheck] DOWN: Shop", "Shop is down: 503", "Target:  https://shop.test"} {
		if !strings.Contains(log, want) {
			t.Errorf("missing %q in\n%s", want, log)
		}
	}
	// The password never goes over a connection without TLS.
	f2 := &fakeSMTP{noTLS: true, got: make(chan string, 1)}
	dialSMTP = func(context.Context, string, bool, string) (net.Conn, error) {
		a, b := net.Pipe()
		go f2.serve(b)
		return a, nil
	}
	if err := m.Send(context.Background(), ev); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("no STARTTLS: %v", err)
	}
	if strings.Contains(<-f2.got, "AUTH") {
		t.Error("logged in without TLS")
	}
}

func TestSendAll(t *testing.T) {
	old := runCmd
	defer func() { runCmd = old }()
	runCmd = func(_ context.Context, _ []string, name string, _ ...string) error {
		if name == "cmd.exe" || name == "sh" {
			return fmt.Errorf("exit status 1")
		}
		return nil
	}
	rs := Send(context.Background(), []Channel{Command{Line: "false"}, Webhook{URL: "http://127.0.0.1:1/"}}, ev)
	if len(rs) != 2 || rs[0].Error == "" || rs[1].Error == "" || rs[0].Channel != "command" {
		t.Errorf("%+v", rs)
	}
	if ev.Title() != "DOWN: Shop" || (Event{Kind: "test"}).Title() != "netcheck test alert" {
		t.Error("titles")
	}
}
