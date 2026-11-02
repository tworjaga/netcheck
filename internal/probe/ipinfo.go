package probe

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// IPInfo describes the connection as the internet sees it.
type IPInfo struct {
	IP      string `json:"public_ip,omitempty"`
	ASN     string `json:"asn,omitempty"` // e.g. "AS8447"
	ISP     string `json:"isp,omitempty"`
	Country string `json:"country,omitempty"`
	Source  string `json:"source,omitempty"` // "cymru" or "ipinfo"
	Error   string `json:"error,omitempty"`
}

// Endpoints that echo the caller's address. They're raced; the first answer
// wins. Variables so tests can point them at local servers.
var publicIPEndpoints = []string{
	"https://api.ipify.org",
	"https://icanhazip.com",
	"https://1.1.1.1/cdn-cgi/trace",
}

// Free fallback when Team Cymru's DNS service isn't reachable.
var ipAPIURL = "https://ipinfo.io/%s/json"

var txtLookup = func(ctx context.Context, name string) ([]string, error) {
	return net.DefaultResolver.LookupTXT(ctx, name)
}

func parsePublicIP(body string) net.IP {
	for _, ln := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(ln), "ip="); ok {
			return net.ParseIP(v)
		}
	}
	return net.ParseIP(strings.TrimSpace(body))
}

// PublicIP asks several services in parallel and returns the first answer.
func PublicIP(ctx context.Context) (net.IP, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ch := make(chan net.IP, len(publicIPEndpoints))
	for _, u := range publicIPEndpoints {
		go func(u string) {
			b, _, err := httpGet(ctx, u, 4096)
			if err != nil {
				ch <- nil
				return
			}
			ch <- parsePublicIP(string(b))
		}(u)
	}
	for range publicIPEndpoints {
		if ip := <-ch; ip != nil {
			return ip, nil
		}
	}
	return nil, errors.New("couldn't find your public IP")
}

// cymruASN resolves ip to an origin ASN, ISP name and country using Team
// Cymru's DNS-based whois (plain TXT lookups; no key, no HTTP).
func cymruASN(ctx context.Context, ip net.IP) (asn, isp, country string, err error) {
	v4 := ip.To4()
	if v4 == nil {
		return "", "", "", errors.New("cymru lookup is IPv4 only here")
	}
	name := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	txt, err := txtLookup(ctx, name)
	if err != nil || len(txt) == 0 {
		return "", "", "", errors.New("no origin record")
	}
	parts := splitPipes(txt[0])
	if len(parts) < 3 || parts[0] == "" {
		return "", "", "", errors.New("unexpected origin record")
	}
	asn = strings.Fields(parts[0])[0]
	country = parts[2]
	if t2, err := txtLookup(ctx, "AS"+asn+".asn.cymru.com"); err == nil && len(t2) > 0 {
		if p := splitPipes(t2[0]); len(p) >= 5 {
			isp = cleanISP(p[4])
		}
	}
	return "AS" + asn, isp, country, nil
}

func splitPipes(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// cleanISP turns "CLOUDFLARENET, US" into "CLOUDFLARENET".
func cleanISP(s string) string {
	if i := strings.LastIndex(s, ","); i > 0 && len(strings.TrimSpace(s[i+1:])) == 2 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func apiASN(ctx context.Context, ip net.IP) (asn, isp, country string, err error) {
	b, _, err := httpGet(ctx, fmt.Sprintf(ipAPIURL, ip), 64<<10)
	if err != nil {
		return "", "", "", err
	}
	var v struct {
		Org     string `json:"org"`
		Country string `json:"country"`
	}
	if err := json.Unmarshal(b, &v); err != nil || v.Org == "" {
		return "", "", "", errors.New("unexpected response")
	}
	asn, isp, _ = strings.Cut(v.Org, " ")
	if !strings.HasPrefix(asn, "AS") {
		return "", v.Org, v.Country, nil
	}
	return asn, isp, v.Country, nil
}

// LookupASN finds the ASN and ISP for ip: Team Cymru first, a free web API
// as the fallback.
func LookupASN(ctx context.Context, ip net.IP) IPInfo {
	info := IPInfo{IP: ip.String()}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	asn, isp, cc, err := cymruASN(c, ip)
	cancel()
	if err == nil {
		info.ASN, info.ISP, info.Country, info.Source = asn, isp, cc, "cymru"
		return info
	}
	c, cancel = context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if asn, isp, cc, err2 := apiASN(c, ip); err2 == nil {
		info.ASN, info.ISP, info.Country, info.Source = asn, isp, cc, "ipinfo"
		return info
	}
	info.Error = "ISP lookup failed"
	return info
}

// GetIPInfo returns the public IP together with its ASN and ISP.
func GetIPInfo(ctx context.Context) IPInfo {
	ip, err := PublicIP(ctx)
	if err != nil {
		return IPInfo{Error: err.Error()}
	}
	return LookupASN(ctx, ip)
}
