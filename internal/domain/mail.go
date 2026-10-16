package domain

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// txtValue joins a TXT record's quoted strings into one value.
func txtValue(data string) string {
	var b strings.Builder
	in := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		switch {
		case c == '"':
			in = !in
		case in && c == '\\' && i+1 < len(data):
			i++
			if i+2 < len(data) && data[i] >= '0' && data[i] <= '9' {
				if n, err := strconv.Atoi(data[i : i+3]); err == nil {
					b.WriteByte(byte(n))
					i += 2
					continue
				}
			}
			b.WriteByte(data[i])
		case in:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// txts returns the TXT values at name that start with prefix (any case).
func txts(ctx context.Context, name, prefix string) ([]string, error) {
	m, err := ask(ctx, name, dnsx.TypeTXT, false)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, rr := range ofType(m.Answer, dnsx.TypeTXT) {
		v := txtValue(rr.Data)
		if strings.HasPrefix(strings.ToLower(v), strings.ToLower(prefix)) {
			out = append(out, v)
		}
	}
	return out, nil
}

func caa(ctx context.Context, zone string) []Check {
	m, err := ask(ctx, zone, dnsx.TypeCAA, false)
	if err != nil {
		return []Check{{AreaCAA, Info, "Couldn't check", err.Error(), ""}}
	}
	recs := ofType(m.Answer, dnsx.TypeCAA)
	if len(recs) == 0 {
		return []Check{{AreaCAA, Info, "No CAA records", "any certificate authority may issue certificates for " + trim(zone),
			`Add CAA records naming the authorities you use, e.g. 0 issue "letsencrypt.org".`}}
	}
	var issue, wild []string
	report := false
	for _, r := range recs {
		f := strings.SplitN(r.Data, " ", 3)
		if len(f) < 3 {
			continue
		}
		v := strings.Trim(f[2], `"`)
		if i := strings.Index(v, ";"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		if v == "" {
			v = "nobody"
		}
		switch strings.ToLower(f[1]) {
		case "issue":
			issue = append(issue, v)
		case "issuewild":
			wild = append(wild, v)
		case "iodef":
			report = true
		}
	}
	d := "may issue: " + strings.Join(issue, ", ")
	if len(issue) == 0 {
		d = "no issue records"
	}
	if len(wild) > 0 {
		d += " · wildcards: " + strings.Join(wild, ", ")
	}
	if report {
		d += " · violations reported"
	}
	return []Check{{AreaCAA, OK, "CAA limits who can issue certificates", d, ""}}
}

// dkimSelectors are the names the big mail services and tools use.
var dkimSelectors = []string{"default", "google", "selector1", "selector2", "k1", "k2", "s1", "s2", "mail", "dkim", "smtp", "mxvault", "zoho", "protonmail", "fm1", "everlytickey1", "mandrill", "sig1"}

func mail(ctx context.Context, zone string) ([]MXHost, []Check) {
	var cs []Check
	var mx []MXHost
	nullMX := false
	m, err := ask(ctx, zone, dnsx.TypeMX, false)
	if err != nil {
		return nil, []Check{{AreaMail, Info, "Couldn't check", err.Error(), ""}}
	}
	for _, rr := range ofType(m.Answer, dnsx.TypeMX) {
		f := strings.Fields(rr.Data)
		if len(f) != 2 {
			continue
		}
		pref, _ := strconv.Atoi(f[0])
		if f[1] == "." {
			nullMX = true
			continue
		}
		mx = append(mx, MXHost{Pref: pref, Host: trim(strings.ToLower(f[1]))})
	}
	sort.SliceStable(mx, func(i, j int) bool { return mx[i].Pref < mx[j].Pref })

	switch {
	case nullMX:
		cs = append(cs, Check{AreaMail, OK, "Takes no mail (null MX)", "", ""})
	case len(mx) == 0:
		cs = append(cs, Check{AreaMail, Info, "No MX records", "mail to " + trim(zone) + " goes to its web address, if anywhere",
			"If the domain sends or takes no mail, publish a null MX (0 .) and the SPF record v=spf1 -all."})
	default:
		var wg sync.WaitGroup
		probs := make([]string, len(mx))
		for i := range mx {
			wg.Add(1)
			go func() {
				defer wg.Done()
				h := mx[i].Host
				if net.ParseIP(h) != nil {
					probs[i] = h + " is an address, not a name"
					return
				}
				cname := false
				for _, t := range []uint16{dnsx.TypeA, dnsx.TypeAAAA} {
					a, err := ask(ctx, h, t, false)
					if err != nil {
						continue
					}
					cname = cname || len(ofType(a.Answer, dnsx.TypeCNAME)) > 0
					for _, rr := range a.Answer {
						if rr.Type == t {
							mx[i].Addrs = append(mx[i].Addrs, rr.Data)
						}
					}
				}
				switch {
				case len(mx[i].Addrs) == 0:
					probs[i] = h + " has no address"
				case cname:
					probs[i] = h + " is an alias (CNAME)"
				}
			}()
		}
		wg.Wait()
		var hosts, bad, odd []string
		for i, x := range mx {
			hosts = append(hosts, fmt.Sprintf("%d %s", x.Pref, x.Host))
			switch {
			case strings.Contains(probs[i], "alias"):
				odd = append(odd, probs[i])
			case probs[i] != "":
				bad = append(bad, probs[i])
			}
		}
		cs = append(cs, Check{AreaMail, OK, plural(len(mx), "mail server", "mail servers"), strings.Join(hosts, ", "), ""})
		if len(bad) > 0 {
			st := Warn
			if len(bad) == len(mx) {
				st = Bad
			}
			cs = append(cs, Check{AreaMail, st, "MX points nowhere", strings.Join(bad, "; "),
				"Point the MX records at host names that have A or AAAA records; mail to the others bounces or waits."})
		}
		if len(odd) > 0 {
			cs = append(cs, Check{AreaMail, Warn, "MX points at an alias", strings.Join(odd, "; "),
				"MX records should name a host directly, not a CNAME (RFC 2181); some senders refuse it."})
		}
	}

	// SPF, DMARC and DKIM in parallel.
	var spf, dmarc []string
	var spfErr, dmarcErr error
	var dkim []string
	var dkimMu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); spf, spfErr = txts(ctx, zone, "v=spf1") }()
	go func() { defer wg.Done(); dmarc, dmarcErr = txts(ctx, "_dmarc."+zone, "v=DMARC1") }()
	if !nullMX && len(mx) > 0 {
		for _, s := range dkimSelectors {
			wg.Add(1)
			go func() {
				defer wg.Done()
				vals, err := txts(ctx, s+"._domainkey."+zone, "")
				if err != nil {
					return
				}
				for _, v := range vals {
					if strings.Contains(v, "p=") {
						dkimMu.Lock()
						dkim = append(dkim, s)
						dkimMu.Unlock()
						return
					}
				}
			}()
		}
	}
	wg.Wait()

	sendsNone := nullMX || len(mx) == 0
	switch {
	case spfErr != nil:
	case len(spf) == 0 && sendsNone:
		cs = append(cs, Check{AreaMail, Warn, "No SPF record", "anyone can send mail claiming to be from " + trim(zone),
			"Publish the TXT record v=spf1 -all to say the domain sends no mail."})
	case len(spf) == 0:
		cs = append(cs, Check{AreaMail, Warn, "No SPF record", "anyone can send mail claiming to be from " + trim(zone),
			"Publish a TXT record listing who sends your mail, e.g. v=spf1 mx include:<your provider> -all."})
	case len(spf) > 1:
		cs = append(cs, Check{AreaMail, Bad, "Two SPF records", "receivers treat that as an error and ignore both",
			"Merge them into one v=spf1 record."})
	default:
		cs = append(cs, spfCheck(spf[0]))
	}

	switch {
	case dmarcErr != nil:
	case len(dmarc) == 0:
		cs = append(cs, Check{AreaMail, Warn, "No DMARC policy", "receivers decide alone what to do with mail that fails SPF or DKIM",
			fmt.Sprintf("Publish a TXT record at _dmarc.%s: v=DMARC1; p=quarantine; rua=mailto:dmarc@%s", trim(zone), trim(zone))})
	case len(dmarc) > 1:
		cs = append(cs, Check{AreaMail, Bad, "Two DMARC records", "receivers ignore both", "Keep one v=DMARC1 record at _dmarc." + trim(zone) + "."})
	default:
		cs = append(cs, dmarcCheck(dmarc[0]))
	}

	if !sendsNone {
		sort.Strings(dkim)
		if len(dkim) > 0 {
			cs = append(cs, Check{AreaMail, OK, "DKIM key found", "selector " + strings.Join(dkim, ", "), ""})
		} else {
			cs = append(cs, Check{AreaMail, Info, "No DKIM key under the common names", "DKIM may still be set up under another selector", ""})
		}
	}
	return mx, cs
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// spfCheck judges an SPF record by how it ends.
func spfCheck(rec string) Check {
	all := ""
	redirect := false
	for _, t := range strings.Fields(strings.ToLower(rec))[1:] {
		switch {
		case strings.HasSuffix(t, "all") && len(t) <= 4:
			all = t
		case strings.HasPrefix(t, "redirect="):
			redirect = true
		}
	}
	switch all {
	case "-all", "~all":
		return Check{AreaMail, OK, "SPF ends in " + all, rec, ""}
	case "all", "+all":
		return Check{AreaMail, Bad, "SPF allows everyone (" + all + ")", rec,
			"End the SPF record in -all (or ~all): +all lets any server on the internet send as you."}
	case "?all":
		return Check{AreaMail, Warn, "SPF is neutral (?all)", rec,
			"End the SPF record in ~all or -all once it lists every sender; ?all protects nothing."}
	}
	if redirect {
		return Check{AreaMail, OK, "SPF redirects to another record", rec, ""}
	}
	return Check{AreaMail, Warn, "SPF has no all at the end", rec, "End the SPF record in ~all or -all, so other senders fail."}
}

// dmarcCheck judges a DMARC record by its policy.
func dmarcCheck(rec string) Check {
	tags := map[string]string{}
	for _, part := range strings.Split(rec, ";") {
		if k, v, ok := strings.Cut(strings.TrimSpace(part), "="); ok {
			tags[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	p := strings.ToLower(tags["p"])
	d := "p=" + p
	if tags["rua"] != "" {
		d += " · reports to " + strings.TrimPrefix(tags["rua"], "mailto:")
	}
	if pct := tags["pct"]; pct != "" && pct != "100" {
		d += " · applied to " + pct + "%"
	}
	switch p {
	case "reject", "quarantine":
		return Check{AreaMail, OK, "DMARC policy: " + p, d, ""}
	case "none":
		return Check{AreaMail, Warn, "DMARC only monitors (p=none)", d,
			"Once the reports show your own mail passing, move to p=quarantine, then p=reject."}
	}
	return Check{AreaMail, Bad, "DMARC record has no valid policy", rec, "Set p=none, p=quarantine or p=reject."}
}

// Blocklists, queried through this computer's own resolver: several lists
// refuse queries that come through the big public resolvers.
var (
	ipLists = []struct{ zone, name string }{
		{"zen.spamhaus.org", "Spamhaus ZEN"}, {"bl.spamcop.net", "SpamCop"},
		{"b.barracudacentral.org", "Barracuda"}, {"psbl.surriel.com", "PSBL"},
	}
	domainList = struct{ zone, name string }{"dbl.spamhaus.org", "Spamhaus DBL"}
	lookupHost = func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	}
)

// listed asks one list: listed, refused (the list won't answer this
// resolver), or neither.
func listed(ctx context.Context, q string) (bool, bool) {
	addrs, err := lookupHost(ctx, q)
	if err != nil {
		return false, false
	}
	for _, a := range addrs {
		if strings.HasPrefix(a, "127.255.255.") {
			return false, true
		}
	}
	for _, a := range addrs {
		if strings.HasPrefix(a, "127.") {
			return true, false
		}
	}
	return false, false
}

func reverse4(ip string) string {
	p := strings.Split(ip, ".")
	return p[3] + "." + p[2] + "." + p[1] + "." + p[0]
}

func blocklists(ctx context.Context, zone string, mx []MXHost) []Check {
	var ips []string
	seen := map[string]bool{}
	for _, m := range mx {
		for _, a := range m.Addrs {
			if ip := net.ParseIP(a); ip != nil && ip.To4() != nil && !seen[a] && len(ips) < 6 {
				seen[a] = true
				ips = append(ips, a)
			}
		}
	}
	type hit struct{ what, list string }
	var mu sync.Mutex
	var hits []hit
	refused := map[string]bool{}
	var wg sync.WaitGroup
	check := func(q, what, list string) {
		defer wg.Done()
		l, r := listed(ctx, q)
		mu.Lock()
		defer mu.Unlock()
		if l {
			hits = append(hits, hit{what, list})
		}
		if r {
			refused[list] = true
		}
	}
	for _, ip := range ips {
		for _, l := range ipLists {
			wg.Add(1)
			go check(reverse4(ip)+"."+l.zone, ip, l.name)
		}
	}
	wg.Add(1)
	go check(trim(zone)+"."+domainList.zone, trim(zone), domainList.name)
	wg.Wait()

	var cs []Check
	sort.Slice(hits, func(i, j int) bool { return hits[i].what+hits[i].list < hits[j].what+hits[j].list })
	for _, h := range hits {
		cs = append(cs, Check{AreaBL, Bad, h.what + " is on " + h.list, "mail from it gets rejected or filtered as spam",
			"Find out why (a hacked account or open relay is the usual cause), fix it, then ask " + h.list + " to remove the listing."})
	}
	if len(hits) == 0 {
		what := trim(zone)
		if len(ips) > 0 {
			what = plural(len(ips), "mail server address", "mail server addresses") + " and " + what
		}
		lists := len(ipLists) + 1
		if len(ips) == 0 {
			lists = 1
		}
		cs = append(cs, Check{AreaBL, OK, "Not listed", what + ", on " + plural(lists-len(refused), "list", "lists"), ""})
	}
	if len(refused) > 0 {
		var r []string
		for l := range refused {
			r = append(r, l)
		}
		sort.Strings(r)
		cs = append(cs, Check{AreaBL, Info, "Couldn't ask " + strings.Join(r, ", "), "the list refuses queries from your DNS resolver; it only answers smaller resolvers", ""})
	}
	return cs
}
