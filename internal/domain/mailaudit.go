package domain

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// Areas of the mail audit, in display order.
const (
	AreaRecords = "Records"
	AreaSPF     = "SPF lookups"
	AreaServers = "Mail servers"
	AreaSTS     = "MTA-STS and TLS-RPT"
)

// MailAreas lists the mail audit's areas in display order.
var MailAreas = []string{AreaRecords, AreaSPF, AreaServers, AreaSTS, AreaBL}

// STSPolicy is a domain's MTA-STS policy.
type STSPolicy struct {
	ID     string   `json:"id"`
	Mode   string   `json:"mode"`
	MX     []string `json:"mx"`
	MaxAge string   `json:"max_age"`
}

// MailReport is the mail audit.
type MailReport struct {
	Domain  string        `json:"domain"`
	MX      []MXHost      `json:"mx"`
	Servers []SMTPServer  `json:"servers"`
	SPF     *SPFCount     `json:"spf,omitempty"`
	STS     *STSPolicy    `json:"mta_sts,omitempty"`
	Checks  []Check       `json:"checks"`
	Score   int           `json:"score"`
	Grade   string        `json:"grade"`
	Took    time.Duration `json:"took_ns"`
	Error   string        `json:"error,omitempty"`
}

// Count tallies the checks by status.
func (r MailReport) Count() (ok, warn, bad int) {
	return Report{Checks: r.Checks}.Count()
}

// maxServers is how many mail servers get a port 25 visit.
const maxServers = 4

// fetchPolicy is a test seam: the MTA-STS policy file over HTTPS.
var fetchPolicy = func(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", err
	}
	c := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirects aren't allowed for the policy")
	}}
	res, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return "", fmt.Errorf("the server answered %s", res.Status)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
	return string(b), err
}

// stsMatches reports whether an MX host fits a policy pattern: exact, or
// "*.example.com" for one label in its place.
func stsMatches(pattern, host string) bool {
	pattern, host = strings.ToLower(trim(pattern)), strings.ToLower(trim(host))
	if strings.HasPrefix(pattern, "*.") {
		_, rest, ok := strings.Cut(host, ".")
		return ok && rest == pattern[2:]
	}
	return pattern == host
}

func parsePolicy(body string) STSPolicy {
	var p STSPolicy
	for _, l := range strings.Split(body, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "mode":
			p.Mode = strings.ToLower(v)
		case "mx":
			p.MX = append(p.MX, v)
		case "max_age":
			p.MaxAge = v
		case "version":
			p.ID = v // overwritten with the TXT id below
		}
	}
	return p
}

func mtaSTS(ctx context.Context, domain string, mx []MXHost) (*STSPolicy, []Check) {
	d := trim(domain)
	recs, err := txts(ctx, "_mta-sts."+d, "v=STSv1")
	if err != nil {
		return nil, nil
	}
	rpt, _ := txts(ctx, "_smtp._tls."+d, "v=TLSRPTv1")
	var cs []Check
	var pol *STSPolicy
	switch {
	case len(recs) == 0:
		cs = append(cs, Check{AreaSTS, Info, "No MTA-STS", "senders fall back to unencrypted delivery if someone strips STARTTLS on the way",
			"Publish an MTA-STS policy (a TXT record at _mta-sts." + d + " and a policy file at https://mta-sts." + d + "/.well-known/mta-sts.txt), in testing mode first."})
	default:
		body, err := fetchPolicy(ctx, "https://mta-sts."+d+"/.well-known/mta-sts.txt")
		if err != nil {
			cs = append(cs, Check{AreaSTS, Bad, "MTA-STS policy can't be fetched", oneLine(err.Error()),
				"Serve the policy at https://mta-sts." + d + "/.well-known/mta-sts.txt with a valid certificate, or remove the _mta-sts record."})
			break
		}
		p := parsePolicy(body)
		for _, kv := range strings.Split(recs[0], ";") {
			if k, v, ok := strings.Cut(strings.TrimSpace(kv), "="); ok && strings.EqualFold(k, "id") {
				p.ID = v
			}
		}
		pol = &p
		var uncovered []string
		for _, m := range mx {
			ok := false
			for _, pat := range p.MX {
				ok = ok || stsMatches(pat, m.Host)
			}
			if !ok {
				uncovered = append(uncovered, m.Host)
			}
		}
		detail := fmt.Sprintf("mode %s · mx %s · max_age %s", p.Mode, strings.Join(p.MX, ", "), p.MaxAge)
		switch {
		case p.Mode != "enforce" && p.Mode != "testing" && p.Mode != "none":
			cs = append(cs, Check{AreaSTS, Bad, "MTA-STS policy has no valid mode", detail, "Set mode: testing or mode: enforce in the policy file."})
		case len(uncovered) > 0 && p.Mode == "enforce":
			cs = append(cs, Check{AreaSTS, Bad, "MTA-STS doesn't cover every mail server", "not covered: " + strings.Join(uncovered, ", "),
				"Add them to the policy's mx: lines; senders that enforce the policy won't deliver to them."})
		case len(uncovered) > 0:
			cs = append(cs, Check{AreaSTS, Warn, "MTA-STS doesn't cover every mail server", "not covered: " + strings.Join(uncovered, ", "),
				"Add them to the policy's mx: lines before switching to enforce."})
		case p.Mode == "enforce":
			cs = append(cs, Check{AreaSTS, OK, "MTA-STS enforced", detail, ""})
		case p.Mode == "testing":
			cs = append(cs, Check{AreaSTS, Info, "MTA-STS in testing mode", detail,
				"Once the TLS reports show no failures, switch the policy to mode: enforce."})
		default:
			cs = append(cs, Check{AreaSTS, Info, "MTA-STS turned off (mode: none)", detail, ""})
		}
	}
	switch {
	case len(rpt) > 0:
		cs = append(cs, Check{AreaSTS, OK, "TLS reports are on", rpt[0], ""})
	case len(recs) > 0:
		cs = append(cs, Check{AreaSTS, Warn, "No TLS-RPT", "nobody hears about delivery failures under MTA-STS",
			"Publish a TXT record at _smtp._tls." + d + ": v=TLSRPTv1; rua=mailto:tls-reports@" + d})
	}
	return pol, cs
}

// ptr finds an address's reverse name and whether it resolves back.
func ptr(ctx context.Context, addr string) (string, bool) {
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", false
	}
	m, err := ask(ctx, dnsx.ReverseName(ip), dnsx.TypePTR, false)
	if err != nil {
		return "", false
	}
	p := ofType(m.Answer, dnsx.TypePTR)
	if len(p) == 0 {
		return "", false
	}
	name := p[0].Data
	t := dnsx.TypeA
	if ip.To4() == nil {
		t = dnsx.TypeAAAA
	}
	f, err := ask(ctx, name, t, false)
	if err != nil {
		return trim(name), false
	}
	for _, rr := range ofType(f.Answer, t) {
		if net.ParseIP(rr.Data).Equal(ip) {
			return trim(name), true
		}
	}
	return trim(name), false
}

// serverChecks judges what the mail servers showed.
func serverChecks(servers []SMTPServer, enforce bool) []Check {
	var cs []Check
	blocked := 0
	for _, s := range servers {
		if s.Blocked {
			blocked++
		}
	}
	if len(servers) > 0 && blocked == len(servers) {
		return []Check{{AreaServers, Info, "Port 25 seems blocked from here", "no mail server answered; many home and mobile ISPs block outgoing port 25",
			"Run netcheck mail from a server (a VPS) to test the mail servers themselves."}}
	}
	for _, s := range servers {
		who := s.Host
		if s.Addr != "" {
			who += " (" + s.Addr + ")"
		}
		switch {
		case s.Blocked:
			cs = append(cs, Check{AreaServers, Warn, who + ": no answer on port 25", "the other servers answered, so this one is likely down or filtered",
				"Check that the server is up and port 25 is open to the internet."})
			continue
		case s.Error != "" && !s.STARTTLS:
			cs = append(cs, Check{AreaServers, Bad, who + ": " + s.Error, s.Banner, "Check the mail server; senders can't deliver to it."})
			continue
		case s.Error != "":
			cs = append(cs, Check{AreaServers, Bad, who + ": " + s.Error, s.Banner,
				"Fix the server's TLS setup (certificate and key, protocol versions); senders that require TLS can't deliver."})
			continue
		case !s.STARTTLS:
			cs = append(cs, Check{AreaServers, Bad, who + ": no STARTTLS", s.Banner,
				"Turn on STARTTLS with a certificate; without it mail to you crosses the internet unencrypted."})
			continue
		}
		detail := fmt.Sprintf("%s · %s · %s, %d days left", shortBanner(s.Banner), s.TLSVersion, s.CertIssuer, s.CertDays)
		st, title, fix := OK, who+": STARTTLS works", ""
		switch {
		case s.CertProblem == "expired" || s.CertDays < 0:
			st, title, fix = Bad, who+": certificate expired", "Renew the mail server's certificate."
		case s.CertProblem == "name" && enforce:
			st, title, fix = Bad, who+": certificate is for another name", "MTA-STS is enforced, so senders refuse it: get a certificate that includes "+s.Host+"."
		case s.CertProblem == "name":
			st, title, fix = Warn, who+": certificate is for another name", "Senders that check (MTA-STS, DANE) would refuse it; get one that includes "+s.Host+"."
		case s.CertProblem == "untrusted":
			st, title, fix = Warn, who+": certificate isn't from a public authority", "Senders that check (MTA-STS) refuse it; use a certificate from a public authority."
		case s.CertDays < 14:
			st, title, fix = Warn, fmt.Sprintf("%s: certificate expires in %d days", who, s.CertDays), "Renew the mail server's certificate."
		case s.TLSVersion == "TLS 1.0" || s.TLSVersion == "TLS 1.1":
			st, title, fix = Warn, who+": old TLS version", "Turn on TLS 1.2 and 1.3 on the mail server."
		}
		cs = append(cs, Check{AreaServers, st, title, detail, fix})
		switch {
		case s.PTR == "":
			cs = append(cs, Check{AreaServers, Warn, s.Addr + " has no reverse DNS", "",
				"Ask whoever runs the address (hosting provider or ISP) for a PTR record naming " + s.Host + "; many receivers reject mail from addresses without one."})
		case !s.PTRMatches:
			cs = append(cs, Check{AreaServers, Warn, s.Addr + " reverse DNS doesn't resolve back", s.PTR,
				"Make the PTR name's A record point back at " + s.Addr + ", or set the PTR to a name that does."})
		}
	}
	return cs
}

// MailAudit checks how a domain receives and protects mail: the records
// (MX, SPF, DMARC, DKIM), SPF's lookup count, each mail server on port 25,
// MTA-STS and TLS-RPT, and the blocklists.
func MailAudit(ctx context.Context, name string) MailReport {
	start := now()
	d := strings.ToLower(dnsx.Fqdn(strings.TrimSpace(name)))
	r := MailReport{Domain: trim(d)}
	defer func() { r.Took = now().Sub(start) }()
	m, err := ask(ctx, d, dnsx.TypeMX, false)
	switch {
	case err != nil:
		r.Error = "couldn't look it up: " + err.Error()
		return r
	case m.Rcode == dnsx.RcodeNXDomain:
		r.Error = r.Domain + " doesn't exist"
		return r
	}

	mx, records := mail(ctx, d)
	for i := range records {
		records[i].Area = AreaRecords
	}
	r.MX = mx
	r.Checks = append(r.Checks, records...)

	var mu sync.Mutex
	var wg sync.WaitGroup
	add := func(cs []Check) {
		mu.Lock()
		r.Checks = append(r.Checks, cs...)
		mu.Unlock()
	}
	hasSPF := false
	for _, c := range records {
		hasSPF = hasSPF || strings.HasPrefix(c.Title, "SPF ")
	}
	if hasSPF {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := countSPF(ctx, d)
			mu.Lock()
			r.SPF = &c
			mu.Unlock()
			add(spfCountChecks(c))
		}()
	}
	var pol *STSPolicy
	var stsChecks []Check
	wg.Add(1)
	go func() { defer wg.Done(); add(blocklists(ctx, d, mx)) }()
	if len(mx) > 0 { // MTA-STS protects mail on its way in
		wg.Add(1)
		go func() { defer wg.Done(); pol, stsChecks = mtaSTS(ctx, d, mx) }()
	}

	// One address per mail server, lowest preference first.
	var targets []SMTPServer
	for _, h := range mx {
		if len(targets) == maxServers {
			break
		}
		addr := ""
		for _, a := range h.Addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil {
				addr = a
				break
			}
		}
		if addr != "" {
			targets = append(targets, SMTPServer{Host: h.Host, Addr: addr})
		}
	}
	r.Servers = make([]SMTPServer, len(targets))
	for i, t := range targets {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := probeSMTP(ctx, t.Host, t.Addr)
			s.PTR, s.PTRMatches = ptr(ctx, t.Addr)
			r.Servers[i] = s
		}()
	}
	wg.Wait()
	r.STS = pol
	r.Checks = append(r.Checks, stsChecks...)
	r.Checks = append(r.Checks, serverChecks(r.Servers, pol != nil && pol.Mode == "enforce")...)

	order := map[string]int{}
	for i, a := range MailAreas {
		order[a] = i
	}
	sort.SliceStable(r.Checks, func(i, j int) bool { return order[r.Checks[i].Area] < order[r.Checks[j].Area] })
	r.Score, r.Grade = grade(r.Checks, pol != nil && pol.Mode == "enforce")
	return r
}

// shortBanner keeps the start of a greeting: the name and software, up
// to the first word that looks like a session id or a date.
func shortBanner(b string) string {
	f := strings.Fields(b)
	for i, w := range f {
		if i >= 2 && (len(w) > 20 || strings.HasSuffix(w, ",") || strings.ContainsAny(w, "0123456789") && len(w) > 12) {
			b = strings.Join(f[:i], " ")
			break
		}
	}
	if len(b) > 60 {
		if i := strings.LastIndex(b[:60], " "); i > 20 {
			return b[:i] + " ..."
		}
		return b[:57] + "..."
	}
	return b
}
