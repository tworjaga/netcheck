// Package rdap looks up who holds a domain, an IP address or an AS number:
// over RDAP (RFC 9082/9083) where the registry offers it, and over classic
// whois (port 43) where it doesn't, as for many country domains.
package rdap

import (
	"bufio"
	"context"
	"encoding/json"

	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Info is what the registry says.
type Info struct {
	Query       string     `json:"query"`
	Kind        string     `json:"kind"` // "domain", "ip", "asn"
	Found       bool       `json:"found"`
	Name        string     `json:"name,omitempty"` // domain name, network name or AS name
	Handle      string     `json:"handle,omitempty"`
	Status      []string   `json:"status,omitempty"`
	Registered  *time.Time `json:"registered,omitempty"`
	Updated     *time.Time `json:"updated,omitempty"`
	Expires     *time.Time `json:"expires,omitempty"`
	Registrar   string     `json:"registrar,omitempty"`
	Holder      string     `json:"holder,omitempty"` // registrant or network holder, when not withheld
	Country     string     `json:"country,omitempty"`
	Abuse       string     `json:"abuse,omitempty"`
	Nameservers []string   `json:"nameservers,omitempty"`
	DNSSEC      *bool      `json:"dnssec,omitempty"`
	Range       string     `json:"range,omitempty"` // IP: first - last
	CIDR        string     `json:"cidr,omitempty"`
	Type        string     `json:"type,omitempty"`
	Source      string     `json:"source"`          // the server asked
	Protocol    string     `json:"protocol"`        // "rdap" or "whois"
	Raw         string     `json:"raw,omitempty"`   // whois text, as sent
	Error       string     `json:"error,omitempty"` // empty when it worked
}

// Test seams.
var (
	httpGet = func(ctx context.Context, url string) (int, []byte, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Accept", "application/rdap+json, application/json")
		c := &http.Client{Timeout: 15 * time.Second}
		res, err := c.Do(req)
		if err != nil {
			return 0, nil, err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
		return res.StatusCode, b, err
	}
	dialWhois = func(ctx context.Context, server string) (net.Conn, error) {
		d := net.Dialer{Timeout: 10 * time.Second}
		return d.DialContext(ctx, "tcp", net.JoinHostPort(server, "43"))
	}
	bootstrapBase = "https://data.iana.org/rdap/"
)

// --- what's being asked ---

var asnRe = regexp.MustCompile(`(?i)^as(\d+)$`)

// Kind tells what a query is.
func Kind(q string) (string, string) {
	q = strings.TrimSpace(q)
	switch {
	case net.ParseIP(q) != nil:
		return "ip", q
	case asnRe.MatchString(q):
		return "asn", asnRe.FindStringSubmatch(q)[1]
	}
	if _, n, err := net.ParseCIDR(q); err == nil {
		return "ip", n.IP.String()
	}
	return "domain", strings.TrimSuffix(strings.ToLower(q), ".")
}

// --- bootstrap: which server knows ---

type bootstrap struct {
	Services [][][]string `json:"services"`
}

func loadBootstrap(ctx context.Context, file string) (bootstrap, error) {
	var b bootstrap
	code, body, err := httpGet(ctx, bootstrapBase+file)
	if err != nil {
		return b, err
	}
	if code != 200 {
		return b, fmt.Errorf("IANA's RDAP list answered %d", code)
	}
	return b, json.Unmarshal(body, &b)
}

// serverFor finds the RDAP base URL for a query, or "" if the registry has
// none.
func serverFor(ctx context.Context, kind, q string) (string, error) {
	file := map[string]string{"domain": "dns.json", "asn": "asn.json", "ip": "ipv4.json"}[kind]
	ip := net.ParseIP(q)
	if kind == "ip" && ip.To4() == nil {
		file = "ipv6.json"
	}
	b, err := loadBootstrap(ctx, file)
	if err != nil {
		return "", err
	}
	best, bestLen := "", -1
	for _, svc := range b.Services {
		if len(svc) < 2 || len(svc[1]) == 0 {
			continue
		}
		url := svc[1][0]
		for _, u := range svc[1] {
			if strings.HasPrefix(u, "https://") {
				url = u
			}
		}
		for _, key := range svc[0] {
			switch kind {
			case "domain":
				tld := q[strings.LastIndex(q, ".")+1:]
				if strings.EqualFold(key, tld) {
					return url, nil
				}
			case "asn":
				lo, hi, _ := strings.Cut(key, "-")
				if hi == "" {
					hi = lo
				}
				n, _ := strconv.ParseUint(q, 10, 32)
				l, _ := strconv.ParseUint(lo, 10, 32)
				h, _ := strconv.ParseUint(hi, 10, 32)
				if n >= l && n <= h {
					return url, nil
				}
			case "ip":
				if _, n, err := net.ParseCIDR(key); err == nil && n.Contains(ip) {
					if ones, _ := n.Mask.Size(); ones > bestLen {
						best, bestLen = url, ones
					}
				}
			}
		}
	}
	return best, nil
}

// --- RDAP answers ---

type entity struct {
	Roles     []string        `json:"roles"`
	Handle    string          `json:"handle"`
	VCard     json.RawMessage `json:"vcardArray"`
	Entities  []entity        `json:"entities"`
	PublicIDs []struct {
		Type, Identifier string
	} `json:"publicIds"`
}

type object struct {
	ObjectClass string   `json:"objectClassName"`
	Handle      string   `json:"handle"`
	LDHName     string   `json:"ldhName"`
	Name        string   `json:"name"`
	Status      []string `json:"status"`
	Events      []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities    []entity `json:"entities"`
	Nameservers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	SecureDNS *struct {
		DelegationSigned *bool `json:"delegationSigned"`
	} `json:"secureDNS"`
	StartAddress string `json:"startAddress"`
	EndAddress   string `json:"endAddress"`
	Type         string `json:"type"`
	Country      string `json:"country"`
	CIDRs        []struct {
		V4Prefix string `json:"v4prefix"`
		V6Prefix string `json:"v6prefix"`
		Length   int    `json:"length"`
	} `json:"cidr0_cidrs"`
	StartAutnum int `json:"startAutnum"`
	Links       []struct {
		Rel, Href, Type string
	} `json:"links"`
	ErrorCode int    `json:"errorCode"`
	Title     string `json:"title"`
}

// vcard pulls the name, organization, e-mail and country out of a jCard.
func vcard(raw json.RawMessage) (fn, org, email, cc string) {
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) != nil || len(arr) < 2 {
		return
	}
	var props [][]json.RawMessage
	if json.Unmarshal(arr[1], &props) != nil {
		return
	}
	str := func(m json.RawMessage) string {
		var s string
		if json.Unmarshal(m, &s) == nil {
			return s
		}
		var ss []string
		if json.Unmarshal(m, &ss) == nil {
			return strings.Join(ss, " ")
		}
		return ""
	}
	for _, p := range props {
		if len(p) < 4 {
			continue
		}
		switch str(p[0]) {
		case "fn":
			fn = str(p[3])
		case "org":
			org = str(p[3])
		case "email":
			email = str(p[3])
		case "adr":
			var params map[string]any
			json.Unmarshal(p[1], &params)
			if c, ok := params["cc"].(string); ok {
				cc = c
			}
			var parts []any
			if json.Unmarshal(p[3], &parts) == nil && len(parts) == 7 {
				if s, ok := parts[6].(string); ok && cc == "" && len(s) <= 3 {
					cc = s
				}
			}
		}
	}
	return
}

func has(roles []string, role string) bool {
	for _, r := range roles {
		if r == role {
			return true
		}
	}
	return false
}

// redacted reports registries' placeholder names for withheld data.
func redacted(s string) bool {
	l := strings.ToLower(s)
	return s == "" || strings.Contains(l, "redacted") || strings.Contains(l, "privacy") || strings.Contains(l, "withheld") || strings.Contains(l, "not disclosed")
}

func parseTime(s string) *time.Time {
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05", "2006-01-02", "20060102", "02.01.2006", "2006.01.02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// fill copies an RDAP object into info, keeping what's already there.
func fill(in *Info, o object) {
	if in.Name == "" {
		in.Name = strings.ToLower(o.LDHName)
		if in.Name == "" {
			in.Name = o.Name
		}
	}
	if in.Handle == "" {
		in.Handle = o.Handle
	}
	if len(in.Status) == 0 {
		in.Status = o.Status
	}
	for _, e := range o.Events {
		t := parseTime(e.Date)
		switch e.Action {
		case "registration":
			if in.Registered == nil {
				in.Registered = t
			}
		case "last changed":
			if in.Updated == nil {
				in.Updated = t
			}
		case "expiration":
			if in.Expires == nil {
				in.Expires = t
			}
		}
	}
	var walk func(es []entity)
	walk = func(es []entity) {
		for _, e := range es {
			fn, org, email, cc := vcard(e.VCard)
			who := org
			if who == "" {
				who = fn
			}
			switch {
			case has(e.Roles, "registrar") && in.Registrar == "":
				in.Registrar = who
			case has(e.Roles, "abuse") && in.Abuse == "" && email != "":
				in.Abuse = email
			case (has(e.Roles, "registrant") || has(e.Roles, "administrative") && in.Kind != "domain") && in.Holder == "" && !redacted(who):
				in.Holder = who
				if in.Country == "" {
					in.Country = cc
				}
			}
			walk(e.Entities)
		}
	}
	walk(o.Entities)
	if len(in.Nameservers) == 0 {
		for _, n := range o.Nameservers {
			in.Nameservers = append(in.Nameservers, strings.ToLower(strings.TrimSuffix(n.LDHName, ".")))
		}
	}
	if in.DNSSEC == nil && o.SecureDNS != nil {
		in.DNSSEC = o.SecureDNS.DelegationSigned
	}
	if o.StartAddress != "" && in.Range == "" {
		in.Range = o.StartAddress + " - " + o.EndAddress
	}
	if in.CIDR == "" {
		var cidrs []string
		for _, c := range o.CIDRs {
			p := c.V4Prefix
			if p == "" {
				p = c.V6Prefix
			}
			cidrs = append(cidrs, fmt.Sprintf("%s/%d", p, c.Length))
		}
		in.CIDR = strings.Join(cidrs, ", ")
	}
	if in.Type == "" {
		in.Type = o.Type
	}
	if in.Country == "" {
		in.Country = o.Country
	}
}

func getObject(ctx context.Context, url string) (object, int, error) {
	var o object
	code, body, err := httpGet(ctx, url)
	if err != nil && ctx.Err() == nil {
		// Registries' servers stall now and then; one more try.
		code, body, err = httpGet(ctx, url)
	}
	if err != nil {
		if strings.Contains(err.Error(), "Timeout") || strings.Contains(err.Error(), "deadline") {
			return o, 0, fmt.Errorf("%s didn't answer in time", hostOf(url))
		}
		return o, 0, err
	}
	if code == 404 {
		return o, 404, nil
	}
	if code != 200 {
		return o, code, fmt.Errorf("the registry answered %d", code)
	}
	return o, code, json.Unmarshal(body, &o)
}

// hostOf is a URL's host name.
func hostOf(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

// Lookup asks the right registry about q.
func Lookup(ctx context.Context, q string) Info {
	kind, key := Kind(q)
	in := Info{Query: q, Kind: kind}
	if kind == "domain" && !strings.Contains(key, ".") {
		in.Error = "give a domain with its ending, like example.com"
		return in
	}
	base, err := serverFor(ctx, kind, key)
	if err != nil {
		// No list, no RDAP: whois still knows.
		base = ""
	}
	if base == "" {
		if kind != "domain" {
			if err != nil {
				in.Error = "couldn't reach IANA's RDAP list: " + err.Error()
			} else {
				in.Error = "no registry publishes RDAP for " + q
			}
			return in
		}
		return whois(ctx, key, in)
	}
	if !strings.HasSuffix(base, "/") {
		base += "/"
	}
	path := map[string]string{"domain": "domain/", "ip": "ip/", "asn": "autnum/"}[kind] + key
	in.Source, in.Protocol = base+path, "rdap"
	o, code, err := getObject(ctx, base+path)
	switch {
	case err != nil:
		in.Error = err.Error()
		return in
	case code == 404:
		return in
	}
	in.Found = true
	fill(&in, o)
	// Thin registries (.com, .net) point at the registrar's own RDAP for
	// the rest.
	for _, l := range o.Links {
		if l.Rel == "related" && strings.Contains(l.Type, "rdap") && l.Href != in.Source {
			if ro, code, err := getObject(ctx, l.Href); err == nil && code == 200 {
				fill(&in, ro)
			}
			break
		}
	}
	sort.Strings(in.Nameservers)
	return in
}

// --- whois, port 43 ---

func whoisQuery(ctx context.Context, server, q string) (string, error) {
	c, err := dialWhois(ctx, server)
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := fmt.Fprintf(c, "%s\r\n", q); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(c, 1<<20))
	if len(b) == 0 && err != nil {
		return "", err
	}
	return string(b), nil
}

// whoisFields are the labels registries use, lower-cased, for each fact.
var whoisFields = map[string][]string{
	"registrar":  {"registrar", "registrar name", "sponsoring registrar", "registrar organization"},
	"created":    {"creation date", "created", "registered", "registered on", "domain registration date", "created date"},
	"updated":    {"updated date", "changed", "last updated", "last modified", "modified"},
	"expires":    {"registry expiry date", "expiry date", "expiration date", "expires", "paid-till", "renewal date", "expire date"},
	"nameserver": {"name server", "nserver", "nameserver", "name servers"},
	"status":     {"domain status", "status", "state"},
	"holder":     {"registrant organization", "registrant", "org", "organization"},
	"abuse":      {"registrar abuse contact email", "abuse-mailbox"},
}

// handleRe matches registry contact handles ("OR13788702-NICAT"), which
// stand where a name would and say nothing.
var handleRe = regexp.MustCompile(`^[A-Z0-9]+-[A-Z0-9]+$`)

var notFound = regexp.MustCompile(`(?i)(no match|not found|no entries found|no data found|status:\s*free|available for registration|nothing found|% no such domain)`)

func parseWhois(text string, in *Info) {
	sc := bufio.NewScanner(strings.NewReader(text))
	field := func(k string) string {
		for f, labels := range whoisFields {
			for _, l := range labels {
				if k == l {
					return f
				}
			}
		}
		return ""
	}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "%") || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">>>") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		switch field(strings.ToLower(strings.TrimSpace(k))) {
		case "registrar":
			if in.Registrar == "" {
				if i := strings.Index(v, "("); i > 0 {
					v = strings.TrimSpace(v[:i])
				}
				in.Registrar = v
			}
		case "created":
			if in.Registered == nil {
				in.Registered = parseTime(strings.Fields(v)[0])
			}
		case "updated":
			if t := parseTime(strings.Fields(v)[0]); t != nil && (in.Updated == nil || t.After(*in.Updated)) {
				in.Updated = t
			}
		case "expires":
			if in.Expires == nil {
				in.Expires = parseTime(strings.Fields(v)[0])
			}
		case "nameserver":
			ns := strings.ToLower(strings.TrimSuffix(strings.Fields(v)[0], "."))
			dup := false
			for _, n := range in.Nameservers {
				dup = dup || n == ns
			}
			if !dup {
				in.Nameservers = append(in.Nameservers, ns)
			}
		case "status":
			in.Status = append(in.Status, strings.Fields(v)[0])
		case "holder":
			if in.Holder == "" && !redacted(v) && !handleRe.MatchString(v) {
				in.Holder = v
			}
		case "abuse":
			if in.Abuse == "" {
				in.Abuse = v
			}
		}
	}
	sort.Strings(in.Nameservers)
}

// whois asks IANA which server holds the domain's ending, then asks it.
func whois(ctx context.Context, domain string, in Info) Info {
	tld := domain[strings.LastIndex(domain, ".")+1:]
	iana, err := whoisQuery(ctx, "whois.iana.org", tld)
	if err != nil {
		in.Error = "couldn't reach whois.iana.org: " + err.Error()
		return in
	}
	server := ""
	for _, l := range strings.Split(iana, "\n") {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "whois") {
			server = strings.TrimSpace(v)
		}
	}
	if server == "" {
		in.Error = "." + tld + " has neither RDAP nor a whois server"
		return in
	}
	text, err := whoisQuery(ctx, server, domain)
	in.Source, in.Protocol = server, "whois"
	if err != nil {
		in.Error = "couldn't reach " + server + ": " + err.Error()
		return in
	}
	in.Raw = text
	if notFound.MatchString(text) && !strings.Contains(strings.ToLower(text), "nserver") && !strings.Contains(strings.ToLower(text), "name server:") {
		return in
	}
	in.Found = true
	in.Name = domain
	parseWhois(text, &in)
	if in.Registrar == "" && in.Registered == nil && len(in.Nameservers) == 0 {
		// Some registries only say "the domain exists" to anonymous queries.
		if strings.Contains(strings.ToLower(text), "restricted") || len(strings.TrimSpace(text)) < 200 {
			in.Status = append(in.Status, "details withheld by the registry")
		}
	}
	return in
}
