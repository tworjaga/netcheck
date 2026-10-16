package rdap

import (
	"bufio"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

var fixtures = map[string]string{
	"https://iana.test/dns.json":  `{"services":[[["com","net"],["http://rdap.verisign.test/com/v1/","https://rdap.verisign.test/com/v1/"]]]}`,
	"https://iana.test/ipv4.json": `{"services":[[["1.0.0.0/8"],["https://rdap.apnic.test/"]],[["1.1.0.0/16"],["https://rdap.narrow.test/"]]]}`,
	"https://iana.test/asn.json":  `{"services":[[["13312-18431"],["https://rdap.arin.test/registry/"]]]}`,
	"https://rdap.verisign.test/com/v1/domain/example.com": `{
		"objectClassName":"domain","ldhName":"EXAMPLE.COM","status":["client transfer prohibited"],
		"events":[{"eventAction":"registration","eventDate":"1995-08-14T04:00:00Z"},{"eventAction":"expiration","eventDate":"2099-08-13T04:00:00Z"}],
		"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RESERVED-Internet Assigned Numbers Authority"]]],
			"entities":[{"roles":["abuse"],"vcardArray":["vcard",[["fn",{},"text","Abuse"],["email",{},"text","abuse@iana.test"]]]}]}],
		"nameservers":[{"ldhName":"B.IANA-SERVERS.NET"},{"ldhName":"A.IANA-SERVERS.NET"}],
		"secureDNS":{"delegationSigned":true},
		"links":[{"rel":"related","href":"https://registrar.test/domain/example.com","type":"application/rdap+json"}]}`,
	"https://registrar.test/domain/example.com": `{"objectClassName":"domain","entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","REDACTED FOR PRIVACY"],["org",{},"text","Example Holder Ltd"],["adr",{"cc":"US"},"text",["","","","","","",""]]]]}]}`,
	"https://rdap.narrow.test/ip/1.1.1.1": `{"objectClassName":"ip network","handle":"1.1.1.0 - 1.1.1.255","name":"APNIC-LABS","type":"ASSIGNED PORTABLE","country":"AU",
		"startAddress":"1.1.1.0","endAddress":"1.1.1.255","cidr0_cidrs":[{"v4prefix":"1.1.1.0","length":24}],
		"entities":[{"roles":["administrative"],"vcardArray":["vcard",[["fn",{},"text","APNIC Research"]]]},{"roles":["abuse"],"vcardArray":["vcard",[["email",{},"text","helpdesk@apnic.test"]]]}]}`,
	"https://rdap.arin.test/registry/autnum/13335": `{"objectClassName":"autnum","handle":"AS13335","name":"CLOUDFLARENET","events":[{"eventAction":"registration","eventDate":"2010-07-14T18:35:57-04:00"}],
		"entities":[{"roles":["registrant"],"vcardArray":["vcard",[["fn",{},"text","Cloudflare, Inc."]]]}]}`,
}

// whoisServers answer port-43 queries: query → reply.
var whoisServers = map[string]map[string]string{
	"whois.iana.org": {"at": "domain:       AT\nwhois:        whois.nic.test\n"},
	"whois.nic.test": {
		"orf.at":    "% Copyright nic.at\ndomain:         orf.at\nregistrar:      APA-IT GmbH ( https://nic.at/registrar/658 )\nregistrant:     OR13788702-NICAT\nnserver:        ns3.apa.at\nnserver:        ns4.apa.net\nchanged:        20241002 10:41:45\n\npersonname:     \norganization:   Oesterreichischer Rundfunk\n",
		"nope.at":   "% nothing found\n",
		"secret.at": "Domain: secret.at\nStatus: connect\n",
	},
}

func useFakes(t *testing.T) {
	t.Helper()
	oldGet, oldDial, oldBase := httpGet, dialWhois, bootstrapBase
	bootstrapBase = "https://iana.test/"
	httpGet = func(_ context.Context, url string) (int, []byte, error) {
		if b, ok := fixtures[url]; ok {
			return 200, []byte(b), nil
		}
		if strings.Contains(url, "rdap.verisign.test") {
			return 404, nil, nil
		}
		return 0, nil, errors.New("no route to " + url)
	}
	dialWhois = func(_ context.Context, server string) (net.Conn, error) {
		answers, ok := whoisServers[server]
		if !ok {
			return nil, errors.New("connection refused")
		}
		c, s := net.Pipe()
		go func() {
			defer s.Close()
			q, _ := bufio.NewReader(s).ReadString('\n')
			s.Write([]byte(answers[strings.TrimSpace(q)]))
		}()
		return c, nil
	}
	t.Cleanup(func() { httpGet, dialWhois, bootstrapBase = oldGet, oldDial, oldBase })
}

func TestKind(t *testing.T) {
	for q, want := range map[string][2]string{
		"Example.COM.": {"domain", "example.com"}, "1.1.1.1": {"ip", "1.1.1.1"}, "2001:db8::1": {"ip", "2001:db8::1"},
		"as13335": {"asn", "13335"}, "AS15169": {"asn", "15169"}, "10.0.0.0/8": {"ip", "10.0.0.0"},
	} {
		if k, key := Kind(q); k != want[0] || key != want[1] {
			t.Errorf("%s: %s %s", q, k, key)
		}
	}
}

func TestLookupRDAP(t *testing.T) {
	useFakes(t)
	in := Lookup(context.Background(), "example.com")
	if in.Error != "" || !in.Found || in.Protocol != "rdap" || in.Name != "example.com" || in.Registrar != "RESERVED-Internet Assigned Numbers Authority" {
		t.Fatalf("domain: %+v", in)
	}
	if in.Abuse != "abuse@iana.test" || in.Holder != "Example Holder Ltd" || in.Country != "US" || in.Registered.Year() != 1995 || in.Expires.Year() != 2099 {
		t.Errorf("details (incl. the registrar's own RDAP): %+v", in)
	}
	if strings.Join(in.Nameservers, ",") != "a.iana-servers.net,b.iana-servers.net" || in.DNSSEC == nil || !*in.DNSSEC {
		t.Errorf("ns/dnssec: %v %v", in.Nameservers, in.DNSSEC)
	}
	if !strings.HasPrefix(in.Source, "https://") {
		t.Errorf("prefers the https server: %s", in.Source)
	}
	if in := Lookup(context.Background(), "free.com"); in.Found || in.Error != "" {
		t.Errorf("not registered: %+v", in)
	}

	ip := Lookup(context.Background(), "1.1.1.1")
	if !ip.Found || ip.CIDR != "1.1.1.0/24" || ip.Name != "APNIC-LABS" || ip.Holder != "APNIC Research" || ip.Abuse != "helpdesk@apnic.test" || !strings.Contains(ip.Source, "narrow") {
		t.Errorf("ip, longest prefix: %+v", ip)
	}
	as := Lookup(context.Background(), "AS13335")
	if !as.Found || as.Name != "CLOUDFLARENET" || as.Holder != "Cloudflare, Inc." || as.Registered == nil {
		t.Errorf("asn: %+v", as)
	}
	if in := Lookup(context.Background(), "AS1"); in.Error == "" {
		t.Error("an AS no registry lists")
	}
	if in := Lookup(context.Background(), "localhost"); in.Error == "" {
		t.Error("a name without an ending")
	}
}

func TestLookupWhois(t *testing.T) {
	useFakes(t)
	in := Lookup(context.Background(), "orf.at")
	if in.Error != "" || !in.Found || in.Protocol != "whois" || in.Source != "whois.nic.test" {
		t.Fatalf("got %+v", in)
	}
	if in.Registrar != "APA-IT GmbH" || in.Holder != "Oesterreichischer Rundfunk" || in.Updated == nil || in.Updated.Year() != 2024 || len(in.Nameservers) != 2 || in.Raw == "" {
		t.Errorf("parsed: %+v", in)
	}
	if in := Lookup(context.Background(), "nope.at"); in.Found || in.Error != "" {
		t.Errorf("not found: %+v", in)
	}
	if in := Lookup(context.Background(), "secret.at"); !in.Found || !strings.Contains(strings.Join(in.Status, " "), "withheld") {
		t.Errorf("withheld: %+v", in)
	}
	whoisServers["whois.iana.org"]["zz"] = "domain: ZZ\n"
	if in := Lookup(context.Background(), "x.zz"); !strings.Contains(in.Error, "neither RDAP nor a whois server") {
		t.Errorf("no server: %q", in.Error)
	}
}
