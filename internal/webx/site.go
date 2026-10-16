package webx

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/domain"
)

// Areas of the site audit, in display order.
const (
	AreaHTTPS   = "HTTPS"
	AreaHSTS    = "HSTS"
	AreaHeaders = "Security headers"
	AreaCookies = "Cookies"
	AreaContent = "Content"
	AreaExtras  = "Extras"
)

// SiteAreas lists the site audit's areas in display order.
var SiteAreas = []string{AreaHTTPS, AreaHSTS, AreaHeaders, AreaCookies, AreaContent, AreaExtras}

// SiteReport is the audit of one website.
type SiteReport struct {
	Target   string         `json:"target"`
	URL      string         `json:"url"`             // where the HTTPS request ended up
	Hops     []Hop          `json:"hops"`            // the HTTPS request
	Plain    []Hop          `json:"plain,omitempty"` // the http:// request, first hop
	Cert     *CertReport    `json:"cert,omitempty"`
	Checks   []domain.Check `json:"checks"`
	Score    int            `json:"score"`
	Grade    string         `json:"grade"`
	CertDays int            `json:"cert_days"` // -1: no certificate seen
	Took     time.Duration  `json:"took_ns"`
	Error    string         `json:"error,omitempty"`
}

// Count tallies the checks by status.
func (r SiteReport) Count() (ok, warn, bad int) {
	return domain.Report{Checks: r.Checks}.Count()
}

// siteFetch is a test seam.
var siteFetch = Fetch

// --- HSTS ---

// HSTS is a parsed Strict-Transport-Security header.
type HSTS struct {
	MaxAge     int64
	Subdomains bool
	Preload    bool
	Valid      bool
}

func parseHSTS(v string) HSTS {
	var h HSTS
	for _, part := range strings.Split(v, ";") {
		k, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "max-age":
			if n, err := strconv.ParseInt(strings.Trim(strings.TrimSpace(val), `"`), 10, 64); err == nil {
				h.MaxAge, h.Valid = n, true
			}
		case "includesubdomains":
			h.Subdomains = true
		case "preload":
			h.Preload = true
		}
	}
	return h
}

const year = 31536000

func humanAge(sec int64) string {
	switch {
	case sec >= year:
		return fmt.Sprintf("%.1f years", float64(sec)/year)
	case sec >= 86400:
		return fmt.Sprintf("%d days", sec/86400)
	}
	return fmt.Sprintf("%d s", sec)
}

func hstsChecks(v string, apex bool) []domain.Check {
	add := func(st domain.Status, title, detail, fix string) domain.Check {
		return domain.Check{Area: AreaHSTS, Status: st, Title: title, Detail: detail, Fix: fix}
	}
	if v == "" {
		return []domain.Check{add(domain.Warn, "No HSTS", "browsers may still try plain http:// first, where the connection can be intercepted",
			"Send Strict-Transport-Security: max-age=31536000; includeSubDomains on every HTTPS response.")}
	}
	h := parseHSTS(v)
	switch {
	case !h.Valid:
		return []domain.Check{add(domain.Bad, "HSTS header is broken", v, "Use Strict-Transport-Security: max-age=31536000; includeSubDomains.")}
	case h.MaxAge == 0:
		return []domain.Check{add(domain.Warn, "HSTS is switched off (max-age=0)", v, "Set max-age=31536000 once HTTPS works everywhere on the site.")}
	case h.MaxAge < year/2:
		return []domain.Check{add(domain.Warn, "HSTS lasts only "+humanAge(h.MaxAge), v, "Raise max-age to at least a year (31536000).")}
	}
	cs := []domain.Check{add(domain.OK, "HSTS for "+humanAge(h.MaxAge), v, "")}
	switch {
	case h.Preload && h.Subdomains && h.MaxAge >= year:
		cs = append(cs, add(domain.OK, "Ready for the browsers' preload list", "includeSubDomains and preload are set", ""))
	case apex && !h.Subdomains:
		cs = append(cs, add(domain.Info, "HSTS doesn't cover subdomains", "", "Add includeSubDomains once every subdomain has HTTPS."))
	}
	return cs
}

// --- headers ---

var versionRe = regexp.MustCompile(`\d+\.\d+`)

func headerChecks(h http.Header) []domain.Check {
	var cs []domain.Check
	add := func(st domain.Status, title, detail, fix string) {
		cs = append(cs, domain.Check{Area: AreaHeaders, Status: st, Title: title, Detail: detail, Fix: fix})
	}
	csp := h.Get("Content-Security-Policy")
	switch {
	case csp == "" && h.Get("Content-Security-Policy-Report-Only") != "":
		add(domain.Info, "Content-Security-Policy only reports", "nothing is blocked yet", "Once the reports are clean, send it as Content-Security-Policy.")
	case csp == "":
		add(domain.Warn, "No Content-Security-Policy", "the browser runs any script that gets into the page",
			"Send a Content-Security-Policy listing where scripts, styles and frames may come from; start with Content-Security-Policy-Report-Only.")
	default:
		lcsp := strings.ToLower(csp)
		script := lcsp
		if i := strings.Index(lcsp, "script-src"); i >= 0 {
			script, _, _ = strings.Cut(lcsp[i:], ";")
		} else if i := strings.Index(lcsp, "default-src"); i >= 0 {
			script, _, _ = strings.Cut(lcsp[i:], ";")
		}
		switch {
		case strings.Contains(script, "'unsafe-inline'") && !strings.Contains(script, "'nonce-") && !strings.Contains(script, "'strict-dynamic'"):
			add(domain.Info, "Content-Security-Policy allows inline scripts", "'unsafe-inline' leaves the door open to injected scripts",
				"Move inline scripts to files, or use nonces, and drop 'unsafe-inline'.")
		default:
			add(domain.OK, "Content-Security-Policy", oneLine(csp), "")
		}
	}
	if strings.EqualFold(strings.TrimSpace(h.Get("X-Content-Type-Options")), "nosniff") {
		add(domain.OK, "X-Content-Type-Options: nosniff", "", "")
	} else {
		add(domain.Warn, "No X-Content-Type-Options: nosniff", "browsers may guess a file's type and run it as script",
			"Send X-Content-Type-Options: nosniff.")
	}
	xfo := strings.ToLower(h.Get("X-Frame-Options"))
	switch {
	case strings.Contains(strings.ToLower(csp), "frame-ancestors"):
		add(domain.OK, "Framing limited (frame-ancestors)", "", "")
	case xfo == "deny" || xfo == "sameorigin":
		add(domain.OK, "Framing limited (X-Frame-Options: "+strings.ToUpper(xfo)+")", "", "")
	default:
		add(domain.Warn, "Other sites can frame this one", "a page can load it invisibly and trick clicks onto it (clickjacking)",
			"Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: SAMEORIGIN).")
	}
	switch rp := strings.ToLower(h.Get("Referrer-Policy")); {
	case rp == "":
		add(domain.Info, "No Referrer-Policy", "browsers' default (strict-origin-when-cross-origin) applies", "")
	case strings.Contains(rp, "unsafe-url") || rp == "no-referrer-when-downgrade":
		add(domain.Warn, "Referrer-Policy: "+rp, "full addresses, with their query strings, go to every other site", "Use Referrer-Policy: strict-origin-when-cross-origin.")
	default:
		add(domain.OK, "Referrer-Policy: "+rp, "", "")
	}
	if h.Get("Permissions-Policy") == "" {
		add(domain.Info, "No Permissions-Policy", "", "Send a Permissions-Policy turning off what the site doesn't use, e.g. camera=(), microphone=(), geolocation=().")
	}
	var leaks []string
	for _, k := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"} {
		if v := h.Get(k); v != "" && (k != "Server" || versionRe.MatchString(v)) {
			leaks = append(leaks, k+": "+v)
		}
	}
	if len(leaks) > 0 {
		add(domain.Info, "Headers name the software version", strings.Join(leaks, "; "),
			"Turn the version off in the server's settings (nginx server_tokens off; Apache ServerTokens Prod; PHP expose_php Off).")
	}
	return cs
}

// --- cookies ---

func cookieChecks(h http.Header) []domain.Check {
	cookies := (&http.Response{Header: h}).Cookies()
	if len(cookies) == 0 {
		return nil
	}
	var insecure, script, nosame []string
	for _, c := range cookies {
		if !c.Secure {
			insecure = append(insecure, c.Name)
		}
		if !c.HttpOnly {
			script = append(script, c.Name)
		}
		if c.SameSite == http.SameSiteDefaultMode {
			nosame = append(nosame, c.Name)
		}
	}
	var cs []domain.Check
	add := func(st domain.Status, title, detail, fix string) {
		cs = append(cs, domain.Check{Area: AreaCookies, Status: st, Title: title, Detail: detail, Fix: fix})
	}
	if len(insecure) > 0 {
		add(domain.Warn, fmt.Sprintf("%d of %d cookies lack Secure", len(insecure), len(cookies)), strings.Join(insecure, ", "),
			"Set the Secure flag, so they're never sent over plain http://.")
	}
	if len(script) > 0 {
		add(domain.Info, fmt.Sprintf("%d of %d cookies readable by scripts (no HttpOnly)", len(script), len(cookies)), strings.Join(script, ", "),
			"Set HttpOnly on cookies that scripts don't need, above all session cookies.")
	}
	if len(nosame) > 0 {
		add(domain.Info, fmt.Sprintf("%d of %d cookies without SameSite", len(nosame), len(cookies)), strings.Join(nosame, ", "),
			"Set SameSite=Lax (or Strict) so other sites can't send them along.")
	}
	if len(cs) == 0 {
		add(domain.OK, fmt.Sprintf("%s set safely", plural(len(cookies), "cookie", "cookies")), "Secure, HttpOnly and SameSite", "")
	}
	return cs
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// --- content ---

// mixedRe finds resources an HTTPS page loads over plain http://. Links
// (<a href>) don't count; what the page itself pulls in does.
var mixedRe = regexp.MustCompile(`(?i)<(script|img|iframe|link|source|video|audio|embed|object)\b[^>]*?\s(?:src|href|data)\s*=\s*["']?(http://[^"'\s>]+)`)

func contentChecks(body []byte, isHTML bool) []domain.Check {
	if !isHTML || len(body) == 0 {
		return nil
	}
	seen := map[string]bool{}
	var active, passive []string
	for _, m := range mixedRe.FindAllSubmatch(body, -1) {
		tag, u := strings.ToLower(string(m[1])), string(m[2])
		if seen[u] {
			continue
		}
		seen[u] = true
		if tag == "script" || tag == "iframe" || tag == "link" || tag == "object" || tag == "embed" {
			active = append(active, u)
		} else {
			passive = append(passive, u)
		}
	}
	sort.Strings(active)
	sort.Strings(passive)
	list := func(us []string) string {
		if len(us) > 3 {
			return strings.Join(us[:3], ", ") + fmt.Sprintf(" and %d more", len(us)-3)
		}
		return strings.Join(us, ", ")
	}
	var cs []domain.Check
	switch {
	case len(active) > 0:
		cs = append(cs, domain.Check{Area: AreaContent, Status: domain.Bad, Title: fmt.Sprintf("Loads %s over plain http://", plural(len(active), "script or style", "scripts or styles")),
			Detail: list(active), Fix: "Load them over https://; browsers block these, which breaks the page."})
	case len(passive) > 0:
		cs = append(cs, domain.Check{Area: AreaContent, Status: domain.Warn, Title: fmt.Sprintf("Loads %s over plain http://", plural(len(passive), "image or media file", "images or media files")),
			Detail: list(passive), Fix: "Load them over https://; browsers upgrade or block them and show the page as not fully secure."})
	default:
		cs = append(cs, domain.Check{Area: AreaContent, Status: domain.OK, Title: "No mixed content", Detail: "everything the page loads comes over HTTPS"})
	}
	return cs
}

// --- the audit ---

// SiteAudit checks a website's HTTPS setup and the protections its
// responses ask browsers for.
func SiteAudit(ctx context.Context, target string, ua string) SiteReport {
	start := time.Now()
	r := SiteReport{Target: target, CertDays: -1}
	defer func() { r.Took = time.Since(start) }()
	u, err := NormalizeURL(target)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	host := u.Hostname()
	path := u.EscapedPath()
	httpsURL := (&url.URL{Scheme: "https", Host: u.Host, Path: path, RawQuery: u.RawQuery}).String()
	plainURL := (&url.URL{Scheme: "http", Host: host, Path: path, RawQuery: u.RawQuery}).String()

	var https, plain, sectxt Result
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		https = siteFetch(ctx, httpsURL, Options{UserAgent: ua, KeepBody: 2 << 20, MaxBody: 8 << 20})
	}()
	go func() {
		defer wg.Done()
		plain = siteFetch(ctx, plainURL, Options{UserAgent: ua, NoFollow: true, MaxBody: 1 << 20})
	}()
	go func() {
		defer wg.Done()
		sectxt = siteFetch(ctx, "https://"+u.Host+"/.well-known/security.txt", Options{UserAgent: ua, NoFollow: true, MaxBody: 64 << 10, KeepBody: 64 << 10})
	}()
	wg.Wait()
	r.Hops, r.Plain = https.Hops, plain.Hops

	if https.Error != "" && len(https.Hops) <= 1 {
		// No HTTPS at all.
		if plain.Error != "" {
			r.Error = "neither https:// nor http:// answered: " + https.Error
			return r
		}
		// TLS may work with a certificate browsers refuse: say what's wrong.
		c := Inspect(ctx, host, 443, "", "")
		if c.Error == "" && c.Problem != "" {
			r.Cert = &c
			if len(c.Chain) > 0 {
				r.CertDays = c.Chain[0].Days
			}
			for _, x := range c.Checks {
				if x.Status != domain.OK {
					x.Area = AreaHTTPS
					r.Checks = append(r.Checks, x)
				}
			}
		} else {
			r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Bad, Title: "No HTTPS", Detail: https.Error,
				Fix: "Get a certificate (Let's Encrypt is free) and serve the site over https://."})
		}
		r.Score, r.Grade = domain.Grade(r.Checks, false)
		r.Score, r.Grade = min(r.Score, 30), "F" // visitors can't open it securely at all
		return r
	}
	final := https.Final()
	r.URL = final.URL
	fu, _ := url.Parse(final.URL)

	// The certificate of the host the visitor ends up on.
	if fu != nil && fu.Scheme == "https" {
		port := 443
		if p, err := strconv.Atoi(fu.Port()); err == nil {
			port = p
		}
		c := Inspect(ctx, fu.Hostname(), port, "", "")
		r.Cert = &c
		if c.Error == "" && len(c.Chain) > 0 {
			r.CertDays = c.Chain[0].Days
		}
		for _, x := range c.Checks {
			if x.Status == domain.OK && x.Title != "Trusted" && !strings.HasPrefix(x.Title, "Valid for") {
				continue // keep the HTTPS area short: trust and expiry, and anything wrong
			}
			x.Area = AreaHTTPS
			r.Checks = append(r.Checks, x)
		}
		if c.Error != "" {
			r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Bad, Title: "Certificate couldn't be read", Detail: c.Error})
		}
	}
	switch {
	case https.Error != "":
		r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Bad, Title: "HTTPS request failed", Detail: https.Error,
			Fix: "Check the redirects and the certificate on " + final.URL + "."})
	case fu != nil && fu.Scheme != "https":
		r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Bad, Title: "HTTPS redirects back to plain http://", Detail: final.URL,
			Fix: "Serve the site on https:// and redirect http:// there, not the other way round."})
	case final.Status >= 400:
		r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Warn, Title: fmt.Sprintf("The page answers %d %s", final.Status, final.StatusText), Detail: final.URL})
	}

	// Plain http:// should send visitors to https:// right away.
	if len(plain.Hops) > 0 {
		p := plain.Hops[0]
		loc, _ := url.Parse(p.Location)
		if loc != nil && p.Location != "" {
			loc = (&url.URL{Scheme: "http", Host: host}).ResolveReference(loc)
		}
		switch {
		case p.Error != "":
			r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Info, Title: "Nothing answers on http://", Detail: p.Error,
				Fix: "Visitors who type the address without https:// get an error; redirect port 80 to https:// instead."})
		case p.Status >= 300 && p.Status < 400 && loc != nil && loc.Scheme == "https":
			code := map[int]string{301: "301", 308: "308"}[p.Status]
			if code == "" {
				r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Info, Title: fmt.Sprintf("http:// redirects to HTTPS with a temporary %d", p.Status), Detail: p.Location,
					Fix: "Use a permanent redirect (301 or 308), so browsers and search engines remember it."})
			} else {
				r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.OK, Title: "http:// redirects to HTTPS", Detail: code + " to " + p.Location})
			}
		default:
			r.Checks = append(r.Checks, domain.Check{Area: AreaHTTPS, Status: domain.Warn, Title: "http:// doesn't redirect to HTTPS", Detail: fmt.Sprintf("it answers %d at %s", p.Status, p.URL),
				Fix: "Redirect every http:// request to https:// with a 301."})
		}
	}

	if fu != nil && fu.Scheme == "https" && https.Error == "" {
		apex := strings.Count(strings.TrimPrefix(fu.Hostname(), "www."), ".") == 1
		r.Checks = append(r.Checks, hstsChecks(final.Header.Get("Strict-Transport-Security"), apex)...)
		r.Checks = append(r.Checks, headerChecks(final.Header)...)
		var setCookies []string
		for _, h := range https.Hops {
			setCookies = append(setCookies, h.Header.Values("Set-Cookie")...)
		}
		r.Checks = append(r.Checks, cookieChecks(http.Header{"Set-Cookie": setCookies})...)
		r.Checks = append(r.Checks, contentChecks(final.Body, strings.Contains(strings.ToLower(final.Header.Get("Content-Type")), "html"))...)

		// Extras.
		if strings.HasPrefix(final.Proto, "HTTP/2") || strings.HasPrefix(final.Proto, "HTTP/3") {
			r.Checks = append(r.Checks, domain.Check{Area: AreaExtras, Status: domain.OK, Title: "HTTP/2"})
		} else {
			r.Checks = append(r.Checks, domain.Check{Area: AreaExtras, Status: domain.Info, Title: "No HTTP/2", Detail: "served as " + final.Proto,
				Fix: "Turn HTTP/2 on in the server; pages with many files load faster."})
		}
		if final.Encoding == "" && final.Size > 4096 && strings.Contains(final.Header.Get("Content-Type"), "html") {
			r.Checks = append(r.Checks, domain.Check{Area: AreaExtras, Status: domain.Info, Title: "The page isn't compressed", Detail: fmt.Sprintf("%d bytes as sent", final.Size),
				Fix: "Turn on gzip or Brotli for text responses."})
		}
		st := sectxt.Final()
		if sectxt.Error == "" && st.Status == 200 && strings.Contains(strings.ToLower(string(st.Body)), "contact:") {
			r.Checks = append(r.Checks, domain.Check{Area: AreaExtras, Status: domain.OK, Title: "security.txt", Detail: "tells researchers where to report problems"})
		} else {
			r.Checks = append(r.Checks, domain.Check{Area: AreaExtras, Status: domain.Info, Title: "No security.txt",
				Fix: "Publish /.well-known/security.txt with a Contact: line, so people who find a problem know where to report it."})
		}
	}

	order := map[string]int{}
	for i, a := range SiteAreas {
		order[a] = i
	}
	sort.SliceStable(r.Checks, func(i, j int) bool { return order[r.Checks[i].Area] < order[r.Checks[j].Area] })
	best := false
	for _, c := range r.Checks {
		best = best || c.Area == AreaHSTS && strings.HasPrefix(c.Title, "Ready for the browsers' preload")
	}
	r.Score, r.Grade = domain.Grade(r.Checks, best)
	if r.Cert != nil && r.Cert.Problem != "" {
		// Browsers refuse the certificate: nothing else matters until that's fixed.
		r.Score, r.Grade = min(r.Score, 30), "F"
	}
	return r
}
