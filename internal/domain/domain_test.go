package domain

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// The DNSKEY and DS example from RFC 4034 section 5.4.
const (
	rfcOwner = "dskey.example.com."
	rfcKey   = "AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw=="
	rfcTag   = 60485
	rfcSHA1  = "2bb183af5f22588179a53b0a98631fad1a292118"
)

func dnskeyRdata(flags uint16, alg uint8, key string) []byte {
	k, _ := base64.StdEncoding.DecodeString(key)
	b := binary.BigEndian.AppendUint16(nil, flags)
	return append(append(b, 3, alg), k...)
}

func TestKeyTagAndDigest(t *testing.T) {
	rd := dnskeyRdata(256, 5, rfcKey)
	if got := keyTag(rd); got != rfcTag {
		t.Errorf("key tag %d, want %d", got, rfcTag)
	}
	if got := dsDigest(rfcOwner, rd, 1); got != rfcSHA1 {
		t.Errorf("SHA-1 digest %s, want %s", got, rfcSHA1)
	}
	if dsDigest("DSKEY.Example.COM", rd, 1) != rfcSHA1 {
		t.Error("the owner name is lower-cased")
	}
}

// fakeNet answers queries from a table: "host name TYPE" (with " rd" for a
// recursive query to a nameserver).
type fakeNet struct {
	msgs map[string]*dnsx.Msg
	down map[string]bool
}

const (
	ns1Addr  = "192.0.2.1"
	ns2Addr  = "198.51.100.1"
	mxAddr   = "203.0.113.25"
	resolver = "1.1.1.1"
)

func (f *fakeNet) exchange(_ context.Context, srv dnsx.Server, q dnsx.Query, _ time.Duration) (*dnsx.Result, error) {
	host, _, _ := net.SplitHostPort(srv.Addr)
	if f.down[host] {
		return nil, errors.New("no answer (timed out)")
	}
	key := host + " " + strings.ToLower(q.Name) + " " + dnsx.TypeString(q.Type)
	if q.Recursion && host != resolver {
		key += " rd"
	}
	if m, ok := f.msgs[key]; ok {
		return &dnsx.Result{Msg: m, RTT: 5 * time.Millisecond}, nil
	}
	if host == resolver {
		return &dnsx.Result{Msg: &dnsx.Msg{RA: true}}, nil
	}
	return &dnsx.Result{Msg: &dnsx.Msg{Rcode: dnsx.RcodeRefused}}, nil
}

func rr(name string, t uint16, data string, raw []byte) dnsx.RR {
	return dnsx.RR{Name: name, Type: t, TTL: 300, Data: data, Raw: raw}
}

func rrsig(exp, inc time.Time) dnsx.RR {
	raw := make([]byte, 18)
	binary.BigEndian.PutUint32(raw[8:], uint32(exp.Unix()))
	binary.BigEndian.PutUint32(raw[12:], uint32(inc.Unix()))
	return rr("example.com.", dnsx.TypeRRSIG, "", raw)
}

var fixedNow = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// healthy is a zone with nothing to fix.
func healthy() *fakeNet {
	key := dnskeyRdata(257, 13, rfcKey)
	ds := binary.BigEndian.AppendUint16(nil, keyTag(key))
	ds = append(ds, 13, 2)
	digest, _ := hex.DecodeString(dsDigest("example.com.", key, 2))
	ds = append(ds, digest...)
	soa := rr("example.com.", dnsx.TypeSOA, "ns1.example.com. hostmaster.example.com. 2026101401 7200 900 1209600 3600", nil)
	sig := rrsig(fixedNow.Add(20*24*time.Hour), fixedNow.Add(-10*24*time.Hour))
	m := map[string]*dnsx.Msg{
		resolver + " example.com. DS":                       {AD: true, Answer: []dnsx.RR{rr("example.com.", dnsx.TypeDS, "", ds)}},
		resolver + " example.com. SOA":                      {AD: true, Answer: []dnsx.RR{soa}},
		resolver + " example.com. CAA":                      {Answer: []dnsx.RR{rr("example.com.", dnsx.TypeCAA, `0 issue "letsencrypt.org"`, nil)}},
		resolver + " example.com. MX":                       {Answer: []dnsx.RR{rr("example.com.", dnsx.TypeMX, "10 mail.example.com.", nil)}},
		resolver + " mail.example.com. A":                   {Answer: []dnsx.RR{rr("mail.example.com.", dnsx.TypeA, mxAddr, nil)}},
		resolver + " example.com. TXT":                      {Answer: []dnsx.RR{rr("example.com.", dnsx.TypeTXT, `"v=spf1 mx " "-all"`, nil), rr("example.com.", dnsx.TypeTXT, `"google-site-verification=x"`, nil)}},
		resolver + " _dmarc.example.com. TXT":               {Answer: []dnsx.RR{rr("_dmarc.example.com.", dnsx.TypeTXT, `"v=DMARC1; p=reject; rua=mailto:d@example.com"`, nil)}},
		resolver + " selector1._domainkey.example.com. TXT": {Answer: []dnsx.RR{rr("x", dnsx.TypeTXT, `"v=DKIM1; k=rsa; p=MIIB"`, nil)}},
	}
	for _, a := range []string{ns1Addr, ns2Addr} {
		m[a+" example.com. SOA"] = &dnsx.Msg{AA: true, Answer: []dnsx.RR{soa, sig}}
		m[a+" example.com. NS"] = &dnsx.Msg{AA: true, Answer: []dnsx.RR{rr("example.com.", dnsx.TypeNS, "ns1.example.com.", nil), rr("example.com.", dnsx.TypeNS, "ns2.example.net.", nil)}}
		m[a+" example.com. DNSKEY"] = &dnsx.Msg{AA: true, Answer: []dnsx.RR{rr("example.com.", dnsx.TypeDNSKEY, "", key), sig}}
	}
	return &fakeNet{msgs: m, down: map[string]bool{}}
}

type certFake struct {
	days    int
	problem string
}

func useNet(t *testing.T, f *fakeNet, listedAs map[string]string, certs map[string]certFake) {
	t.Helper()
	oldEx, oldTr, oldRes, oldNow, oldLook, oldTLS := exchange, trace, resolvers, now, lookupHost, dialTLS
	exchange, resolvers, now = f.exchange, []string{resolver}, func() time.Time { return fixedNow }
	trace = func(context.Context, string, uint16, dnsx.TraceOptions) dnsx.TraceResult {
		return dnsx.TraceResult{Final: "answer", Steps: []dnsx.TraceStep{
			{Zone: "com.", Next: "example.com.", NextNS: []dnsx.NS{{Name: "ns1.example.com.", Addr: ns1Addr}, {Name: "ns2.example.net.", Addr: ns2Addr}}},
			{Zone: "example.com."},
		}}
	}
	lookupHost = func(_ context.Context, q string) ([]string, error) {
		if a, ok := listedAs[q]; ok {
			return []string{a}, nil
		}
		return nil, errors.New("no such host")
	}
	dialTLS = func(_ context.Context, host string) (*certInfo, error) {
		c, ok := certs[host]
		if !ok {
			return nil, errors.New("connection refused")
		}
		leaf := &x509.Certificate{NotAfter: fixedNow.Add(time.Duration(c.days)*24*time.Hour + time.Hour), DNSNames: []string{"other.example"}}
		leaf.Issuer.Organization = []string{"Let's Encrypt"}
		return &certInfo{Leaf: leaf, Version: 0x0304, Problem: c.problem}, nil
	}
	t.Cleanup(func() {
		exchange, trace, resolvers, now, lookupHost, dialTLS = oldEx, oldTr, oldRes, oldNow, oldLook, oldTLS
	})
}

func find(r Report, area, title string) *Check {
	for i, c := range r.Checks {
		if c.Area == area && strings.Contains(c.Title, title) {
			return &r.Checks[i]
		}
	}
	return nil
}

func TestAuditHealthy(t *testing.T) {
	useNet(t, healthy(), nil, map[string]certFake{"example.com": {days: 60}, "www.example.com": {days: 60}})
	r := Audit(context.Background(), "example.com")
	_, warn, bad := r.Count()
	if r.Error != "" || warn != 0 || bad != 0 || r.Grade != "A+" || r.CertDays != 60 {
		for _, c := range r.Checks {
			t.Logf("%s %s: %s (%s)", c.Status, c.Area, c.Title, c.Detail)
		}
		t.Fatalf("grade %s, %d warnings, %d problems, cert %d, error %q", r.Grade, warn, bad, r.CertDays, r.Error)
	}
	for _, want := range [][2]string{
		{AreaNS, "2 nameservers"}, {AreaSOA, "Timers are sensible"}, {AreaDNSSEC, "chain validates"},
		{AreaDNSSEC, "valid for 20 more days"}, {AreaCAA, "limits"}, {AreaMail, "1 mail server"},
		{AreaMail, "SPF ends in -all"}, {AreaMail, "DMARC policy: reject"}, {AreaMail, "DKIM key found"},
		{AreaBL, "Not listed"}, {AreaWeb, "www.example.com: valid for 60"},
	} {
		if find(r, want[0], want[1]) == nil {
			t.Errorf("missing %s: %s", want[0], want[1])
		}
	}
	if c := find(r, AreaSOA, "Timers"); !strings.Contains(c.Detail, "hostmaster@example.com") {
		t.Errorf("contact: %s", c.Detail)
	}
	if len(r.MX) != 1 || r.MX[0].Addrs[0] != mxAddr {
		t.Errorf("mx: %+v", r.MX)
	}
	// Shown in area order.
	last := -1
	for _, c := range r.Checks {
		i := 0
		for j, a := range Areas {
			if a == c.Area {
				i = j
			}
		}
		if i < last {
			t.Fatalf("checks out of order at %s", c.Area)
		}
		last = i
	}
}

func TestAuditProblems(t *testing.T) {
	f := healthy()
	f.down[ns2Addr] = true
	// ns1 resolves anything for anyone.
	f.msgs[ns1Addr+" example.org. A rd"] = &dnsx.Msg{RA: true, Answer: []dnsx.RR{rr("example.org.", dnsx.TypeA, "192.0.2.80", nil)}}
	// The DS is for some other key.
	f.msgs[resolver+" example.com. DS"].Answer[0].Raw[0] ^= 0xFF
	f.msgs[resolver+" example.com. TXT"].Answer[0].Data = `"v=spf1 +all"`
	f.msgs[resolver+" _dmarc.example.com. TXT"].Answer[0].Data = `"v=DMARC1; p=none"`
	listed := map[string]string{"25.113.0.203.zen.spamhaus.org": "127.0.0.2", "25.113.0.203.bl.spamcop.net": "127.255.255.254"}
	useNet(t, f, listed, map[string]certFake{"example.com": {days: 5}, "www.example.com": {days: 60, problem: "name"}})
	r := Audit(context.Background(), "example.com")

	for _, want := range []struct {
		area, title string
		st          Status
	}{
		{AreaNS, "1 of 2 nameservers don't answer", Warn},
		{AreaNS, "Open resolver: ns1.example.com", Bad},
		{AreaDNSSEC, "doesn't match any key", Bad},
		{AreaMail, "SPF allows everyone", Bad},
		{AreaMail, "DMARC only monitors", Warn},
		{AreaBL, "203.0.113.25 is on Spamhaus ZEN", Bad},
		{AreaBL, "Couldn't ask SpamCop", Info},
		{AreaWeb, "example.com: certificate expires in 5 days", Bad},
		{AreaWeb, "www.example.com: certificate is for another name", Bad},
	} {
		c := find(r, want.area, want.title)
		if c == nil {
			t.Errorf("missing %s: %s", want.area, want.title)
			continue
		}
		if c.Status != want.st {
			t.Errorf("%s: status %s, want %s", want.title, c.Status, want.st)
		}
		if (c.Status == Bad || c.Status == Warn) && c.Fix == "" {
			t.Errorf("%s has no fix", want.title)
		}
	}
	if r.Grade != "F" || r.CertDays != 5 {
		t.Errorf("grade %s (%d), cert %d", r.Grade, r.Score, r.CertDays)
	}
}

func TestAuditSubdomainAndMissing(t *testing.T) {
	useNet(t, healthy(), nil, nil)
	r := Audit(context.Background(), "WWW.Example.com")
	if r.Domain != "example.com" || r.Asked != "www.example.com" {
		t.Errorf("a name in the zone audits the zone: %q %q", r.Domain, r.Asked)
	}
	trace = func(context.Context, string, uint16, dnsx.TraceOptions) dnsx.TraceResult {
		return dnsx.TraceResult{Final: "nxdomain", Steps: []dnsx.TraceStep{{Zone: "com."}}}
	}
	if r := Audit(context.Background(), "nope.com"); r.Error != "nope.com doesn't exist" {
		t.Errorf("missing: %q", r.Error)
	}
}

func TestDNSSECStates(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(f *fakeNet)
		title string
		st    Status
	}{
		{"unsigned", func(f *fakeNet) {
			delete(f.msgs, resolver+" example.com. DS")
			for _, a := range []string{ns1Addr, ns2Addr} {
				delete(f.msgs, a+" example.com. DNSKEY")
			}
		}, "Not signed", Info},
		{"no DS", func(f *fakeNet) { delete(f.msgs, resolver+" example.com. DS") }, "registry has no DS", Warn},
		{"no keys", func(f *fakeNet) {
			for _, a := range []string{ns1Addr, ns2Addr} {
				delete(f.msgs, a+" example.com. DNSKEY")
			}
		}, "zone has no keys", Bad},
		{"servfail", func(f *fakeNet) {
			f.msgs[resolver+" example.com. SOA"] = &dnsx.Msg{Rcode: dnsx.RcodeServFail}
		}, "don't validate", Bad},
		{"expired", func(f *fakeNet) {
			old := rrsig(fixedNow.Add(-time.Hour), fixedNow.Add(-30*24*time.Hour))
			f.msgs[ns1Addr+" example.com. DNSKEY"].Answer[1] = old
		}, "have expired", Bad},
		{"on the fly", func(f *fakeNet) {
			fresh := rrsig(fixedNow.Add(30*time.Hour), fixedNow.Add(-18*time.Hour))
			f.msgs[ns1Addr+" example.com. DNSKEY"].Answer[1] = fresh
			f.msgs[ns1Addr+" example.com. SOA"].Answer[1] = fresh
		}, "renewed continuously", OK},
		{"on the fly, stuck", func(f *fakeNet) {
			stuck := rrsig(fixedNow.Add(3*time.Hour), fixedNow.Add(-45*time.Hour))
			f.msgs[ns1Addr+" example.com. DNSKEY"].Answer[1] = stuck
		}, "expire in 3 h", Warn},
	}
	for _, c := range cases {
		f := healthy()
		c.edit(f)
		useNet(t, f, nil, nil)
		r := Audit(context.Background(), "example.com")
		got := find(r, AreaDNSSEC, c.title)
		if got == nil || got.Status != c.st {
			var have []string
			for _, x := range r.Checks {
				if x.Area == AreaDNSSEC {
					have = append(have, string(x.Status)+" "+x.Title)
				}
			}
			t.Errorf("%s: want %s %q, have %v", c.name, c.st, c.title, have)
		}
	}
}

func TestSerialsByProvider(t *testing.T) {
	f := healthy()
	other := rr("example.com.", dnsx.TypeSOA, "ns1.example.com. hostmaster.example.com. 7 7200 900 1209600 3600", nil)
	f.msgs[ns2Addr+" example.com. SOA"] = &dnsx.Msg{AA: true, Answer: []dnsx.RR{other}}
	useNet(t, f, nil, nil)
	// ns1.example.com and ns2.example.net count as one provider ("example").
	if c := find(Audit(context.Background(), "example.com"), AreaNS, "different versions"); c == nil || c.Status != Warn {
		t.Errorf("one provider, two serials: %+v", c)
	}
	if provider("ns-1707.awsdns-21.co.uk.") != "awsdns" || provider("dns1.p08.nsone.net") != "nsone" || provider("ns-520.awsdns-01.net") != "awsdns" {
		t.Error("provider names")
	}
}

func TestRecordParsing(t *testing.T) {
	if got := txtValue(`"v=spf1 include:a.example " "-all"`); got != "v=spf1 include:a.example -all" {
		t.Errorf("txt join: %q", got)
	}
	if got := txtValue(`"a\"b\059c"`); got != `a"b;c` {
		t.Errorf("txt escapes: %q", got)
	}
	for rec, want := range map[string]Status{
		"v=spf1 mx -all": OK, "v=spf1 ~all": OK, "v=spf1 ?all": Warn, "v=spf1 +all": Bad,
		"v=spf1 all": Bad, "v=spf1 mx": Warn, "v=spf1 redirect=_spf.example.com": OK,
	} {
		if got := spfCheck(rec).Status; got != want {
			t.Errorf("%s: %s, want %s", rec, got, want)
		}
	}
	for rec, want := range map[string]Status{
		"v=DMARC1; p=reject": OK, "v=DMARC1;p=quarantine;pct=50": OK, "v=DMARC1; p=none": Warn, "v=DMARC1; rua=mailto:x@y": Bad,
	} {
		if got := dmarcCheck(rec).Status; got != want {
			t.Errorf("%s: %s, want %s", rec, got, want)
		}
	}
	if c := dmarcCheck("v=DMARC1;p=quarantine;pct=50"); !strings.Contains(c.Detail, "50%") {
		t.Errorf("pct: %s", c.Detail)
	}
	if contact(`john\.smith.example.com.`) != "john.smith@example.com" || contact("hostmaster.example.com.") != "hostmaster@example.com" {
		t.Error("contact")
	}
	if cs := soaChecks(rr("x.", dnsx.TypeSOA, "a. b. 1 300 600 86400 5", nil)); cs[0].Status != Info || !strings.Contains(cs[0].Detail, "expire 1 d") {
		t.Errorf("odd timers: %+v", cs[0])
	}
}

func TestGrade(t *testing.T) {
	c := func(st Status, title string) Check { return Check{Area: AreaDNSSEC, Status: st, Title: title} }
	cases := []struct {
		cs   []Check
		want string
	}{
		{[]Check{c(OK, "Signed, and the chain validates")}, "A+"},
		{[]Check{c(Info, "Not signed")}, "A"},
		{[]Check{c(Warn, "x")}, "A"},
		{[]Check{c(Warn, "x"), c(Warn, "y")}, "A-"},
		{[]Check{c(Bad, "x")}, "C"},
		{[]Check{c(Bad, "x"), c(Bad, "y"), c(Bad, "z")}, "E"},
	}
	for _, x := range cases {
		if _, g := grade(x.cs, x.want == "A+"); g != x.want {
			t.Errorf("%v: %s, want %s", x.cs, g, x.want)
		}
	}
}
