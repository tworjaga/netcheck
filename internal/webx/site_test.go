package webx

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/domain"
)

func find(cs []domain.Check, title string) *domain.Check {
	for i := range cs {
		if strings.Contains(cs[i].Title, title) {
			return &cs[i]
		}
	}
	return nil
}

func TestHSTS(t *testing.T) {
	h := parseHSTS(`max-age="31536000"; includeSubDomains; preload`)
	if !h.Valid || h.MaxAge != year || !h.Subdomains || !h.Preload {
		t.Errorf("%+v", h)
	}
	cases := []struct {
		v     string
		apex  bool
		title string
		st    domain.Status
	}{
		{"", true, "No HSTS", domain.Warn},
		{"max-age=abc", true, "broken", domain.Bad},
		{"max-age=0", true, "switched off", domain.Warn},
		{"max-age=2592000", true, "only 30 days", domain.Warn},
		{"max-age=63072000; includeSubDomains; preload", true, "preload list", domain.OK},
		{"max-age=31536000", true, "doesn't cover subdomains", domain.Info},
		{"max-age=31536000", false, "HSTS for 1.0 years", domain.OK},
	}
	for _, c := range cases {
		got := find(hstsChecks(c.v, c.apex), c.title)
		if got == nil || got.Status != c.st {
			t.Errorf("%q: want %s %q, got %+v", c.v, c.st, c.title, hstsChecks(c.v, c.apex))
		}
	}
	if find(hstsChecks("max-age=31536000", false), "subdomains") != nil {
		t.Error("a subdomain isn't told to cover subdomains")
	}
}

func TestHeaderChecks(t *testing.T) {
	good := http.Header{}
	good.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	good.Set("X-Content-Type-Options", "nosniff")
	good.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	good.Set("Permissions-Policy", "camera=()")
	good.Set("Server", "nginx")
	for _, c := range headerChecks(good) {
		if c.Status != domain.OK {
			t.Errorf("good headers: %+v", c)
		}
	}
	bad := http.Header{}
	bad.Set("Server", "Apache/2.4.41 (Ubuntu)")
	bad.Set("X-Powered-By", "PHP/7.4.3")
	bad.Set("Referrer-Policy", "unsafe-url")
	cs := headerChecks(bad)
	for title, st := range map[string]domain.Status{
		"No Content-Security-Policy": domain.Warn, "No X-Content-Type-Options": domain.Warn, "Other sites can frame": domain.Warn,
		"Referrer-Policy: unsafe-url": domain.Warn, "No Permissions-Policy": domain.Info, "software version": domain.Info,
	} {
		if c := find(cs, title); c == nil || c.Status != st {
			t.Errorf("%s: %+v", title, c)
		}
	}
	if c := find(cs, "software version"); !strings.Contains(c.Detail, "Apache/2.4.41") || !strings.Contains(c.Detail, "PHP/7.4.3") {
		t.Errorf("leaks: %s", c.Detail)
	}
	inline := http.Header{}
	inline.Set("Content-Security-Policy", "script-src 'self' 'unsafe-inline'; object-src 'none'")
	inline.Set("X-Frame-Options", "SAMEORIGIN")
	cs = headerChecks(inline)
	if c := find(cs, "inline scripts"); c == nil || c.Status != domain.Info {
		t.Errorf("unsafe-inline: %+v", cs)
	}
	if c := find(cs, "X-Frame-Options: SAMEORIGIN"); c == nil {
		t.Error("X-Frame-Options counts for framing")
	}
	nonce := http.Header{}
	nonce.Set("Content-Security-Policy", "script-src 'nonce-abc' 'unsafe-inline' 'strict-dynamic'")
	if find(headerChecks(nonce), "inline scripts") != nil {
		t.Error("with a nonce, unsafe-inline is ignored by browsers")
	}
}

func TestCookieChecks(t *testing.T) {
	h := http.Header{"Set-Cookie": {"session=1; Secure; HttpOnly; SameSite=Lax", "pref=x; Path=/", "track=y; Secure"}}
	cs := cookieChecks(h)
	if c := find(cs, "lack Secure"); c == nil || c.Status != domain.Warn || c.Detail != "pref" {
		t.Errorf("secure: %+v", cs)
	}
	if c := find(cs, "no HttpOnly"); c == nil || c.Detail != "pref, track" {
		t.Errorf("httponly: %+v", cs)
	}
	if cs := cookieChecks(http.Header{"Set-Cookie": {"a=1; Secure; HttpOnly; SameSite=Strict"}}); len(cs) != 1 || cs[0].Status != domain.OK {
		t.Errorf("safe: %+v", cs)
	}
	if cookieChecks(http.Header{}) != nil {
		t.Error("no cookies, no checks")
	}
}

func TestContentChecks(t *testing.T) {
	page := `<html><a href="http://example.com/">a link is fine</a>
		<img src="http://cdn.example.com/a.png"><img src='http://cdn.example.com/a.png'>
		<script src="http://cdn.example.com/x.js"></script><link rel=stylesheet href=http://cdn.example.com/s.css>`
	cs := contentChecks([]byte(page), true)
	if len(cs) != 1 || cs[0].Status != domain.Bad || !strings.Contains(cs[0].Title, "2 scripts or styles") {
		t.Errorf("active: %+v", cs)
	}
	cs = contentChecks([]byte(`<img src="http://cdn.example.com/a.png"><a href="http://x">`), true)
	if len(cs) != 1 || cs[0].Status != domain.Warn || !strings.Contains(cs[0].Title, "1 image") {
		t.Errorf("passive: %+v", cs)
	}
	if cs := contentChecks([]byte(`<script src="https://x/a.js"></script>`), true); cs[0].Status != domain.OK {
		t.Errorf("clean: %+v", cs)
	}
	if contentChecks([]byte(`<img src="http://x">`), false) != nil {
		t.Error("only HTML pages are scanned")
	}
}

// siteNet answers the audit's three requests from a table.
func useSite(t *testing.T, pages map[string]Result) {
	t.Helper()
	old := siteFetch
	siteFetch = func(_ context.Context, u string, _ Options) Result {
		if r, ok := pages[u]; ok {
			return r
		}
		return Result{Hops: []Hop{{URL: u, Error: "connection refused"}}, Error: "connection refused"}
	}
	t.Cleanup(func() { siteFetch = old })
}

func TestSiteAudit(t *testing.T) {
	future := time.Now().Add(200 * 24 * time.Hour)
	root := issue(t, nil, "Test Root", true, future)
	leaf := issue(t, root, "site.test", false, future, "site.test")
	roots := x509.NewCertPool()
	roots.AddCert(root.cert)
	serve(t, certServer{chain: []*pki{leaf}}, roots)

	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Permissions-Policy", "camera=()")
	h.Set("Content-Type", "text/html")
	h.Add("Set-Cookie", "s=1; Secure; HttpOnly; SameSite=Lax")
	useSite(t, map[string]Result{
		"https://site.test/":                         {Hops: []Hop{{URL: "https://site.test/", Status: 200, Proto: "HTTP/2.0", Header: h, Encoding: "gzip", Size: 9000, Body: []byte(`<script src="/a.js"></script>`)}}},
		"http://site.test/":                          {Hops: []Hop{{URL: "http://site.test/", Status: 301, Location: "https://site.test/"}}},
		"https://site.test/.well-known/security.txt": {Hops: []Hop{{Status: 200, Body: []byte("Contact: mailto:security@site.test\n")}}},
	})
	r := SiteAudit(context.Background(), "site.test", "test")
	_, warn, bad := r.Count()
	if r.Error != "" || r.Grade != "A+" || warn+bad != 0 || r.CertDays < 190 {
		for _, c := range r.Checks {
			t.Logf("%s %s: %s", c.Status, c.Area, c.Title)
		}
		t.Fatalf("grade %s, %d warnings, %d problems, %q", r.Grade, warn, bad, r.Error)
	}
	for _, title := range []string{"Trusted", "redirects to HTTPS", "preload list", "Content-Security-Policy", "set safely", "No mixed content", "HTTP/2", "security.txt"} {
		if find(r.Checks, title) == nil {
			t.Errorf("missing %q", title)
		}
	}

	// Plain http:// that stays plain, a temporary redirect, and no HTTPS at all.
	useSite(t, map[string]Result{
		"https://site.test/": {Hops: []Hop{{URL: "https://site.test/", Status: 200, Proto: "HTTP/1.1", Header: http.Header{"Content-Type": {"text/html"}}}}},
		"http://site.test/":  {Hops: []Hop{{URL: "http://site.test/", Status: 200}}},
	})
	if c := find(SiteAudit(context.Background(), "site.test", "test").Checks, "doesn't redirect"); c == nil || c.Status != domain.Warn {
		t.Errorf("no redirect: %+v", c)
	}
	useSite(t, map[string]Result{
		"https://site.test/": {Hops: []Hop{{URL: "https://site.test/", Status: 200, Header: http.Header{}}}},
		"http://site.test/":  {Hops: []Hop{{URL: "http://site.test/", Status: 302, Location: "https://site.test/"}}},
	})
	if c := find(SiteAudit(context.Background(), "site.test", "test").Checks, "temporary 302"); c == nil || c.Status != domain.Info {
		t.Errorf("302: %+v", c)
	}

	// A certificate browsers refuse: the audit names it and grades F.
	expired := issue(t, root, "site.test", false, time.Now().Add(-time.Hour), "site.test")
	serve(t, certServer{chain: []*pki{expired}}, roots)
	useSite(t, map[string]Result{
		"https://site.test/": {Hops: []Hop{{URL: "https://site.test/", Error: "the certificate expired"}}, Error: "the certificate expired"},
		"http://site.test/":  {Hops: []Hop{{URL: "http://site.test/", Status: 301, Location: "https://site.test/"}}},
	})
	r = SiteAudit(context.Background(), "site.test", "test")
	if r.Grade != "F" || r.Score > 30 || find(r.Checks, "Expired") == nil {
		t.Errorf("expired: %s %d %+v", r.Grade, r.Score, r.Checks)
	}

	old := dialCert
	dialCert = func(context.Context, string) (net.Conn, error) { return nil, errors.New("refused") }
	defer func() { dialCert = old }()
	useSite(t, map[string]Result{
		"https://site.test/": {Hops: []Hop{{Error: "connection refused"}}, Error: "connection refused"},
		"http://site.test/":  {Hops: []Hop{{URL: "http://site.test/", Status: 200}}},
	})
	if r := SiteAudit(context.Background(), "site.test", "test"); r.Grade != "F" || find(r.Checks, "No HTTPS") == nil {
		t.Errorf("no https: %s %+v", r.Grade, r.Checks)
	}
	useSite(t, nil)
	if r := SiteAudit(context.Background(), "site.test", "test"); !strings.Contains(r.Error, "neither") {
		t.Errorf("nothing answers: %q", r.Error)
	}
}
