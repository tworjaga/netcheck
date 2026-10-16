package probe

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// NATInfo says whether more than one layer of address translation sits
// between this machine and the internet.
type NATInfo struct {
	Kind     string `json:"kind"` // "none", "double", "cgnat", "unknown"
	RouterIP string `json:"router_wan_ip,omitempty"`
	Public   string `json:"public_ip,omitempty"`
	Method   string `json:"method,omitempty"` // "upnp" or "route"
	Detail   string `json:"detail"`
}

var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLoopback()
}

// ClassifyNAT compares the router's WAN address with the public address.
func ClassifyNAT(wan, public net.IP) NATInfo {
	n := NATInfo{Method: "upnp", RouterIP: wan.String()}
	if public != nil {
		n.Public = public.String()
	}
	switch {
	case cgnatNet.Contains(wan):
		n.Kind = "cgnat"
		n.Detail = "Your router's internet address is in the carrier-grade NAT range (100.64.0.0/10), so your ISP shares one public address between many customers. Hosting servers or port forwarding won't work."
	case isPrivate(wan):
		n.Kind = "double"
		n.Detail = "Your router's internet address is private, so there's another router or NAT in front of it (double NAT). Port forwarding and some games and calls can break."
	case public != nil && !wan.Equal(public):
		n.Kind = "cgnat"
		n.Detail = "Your router reports a different public address than the internet sees, so your ISP translates your traffic a second time (carrier-grade NAT)."
	default:
		n.Kind = "none"
		n.Detail = "Your router has a public address of its own. No extra NAT layers."
	}
	return n
}

// NATFromHops is the fallback when the router can't tell us its WAN address:
// look at the first hops past the gateway on the way out.
func NATFromHops(gw net.IP, hops []net.IP) NATInfo {
	n := NATInfo{Method: "route"}
	for _, h := range hops {
		if h == nil || h.Equal(gw) {
			continue
		}
		switch {
		case cgnatNet.Contains(h):
			n.Kind, n.Detail = "cgnat", fmt.Sprintf("The first hop past your router (%s) is in the carrier-grade NAT range, so your ISP shares addresses between customers.", h)
		case isPrivate(h):
			n.Kind, n.Detail = "double", fmt.Sprintf("The first hop past your router (%s) is a private address, which points to a second router or NAT in front of yours.", h)
		default:
			n.Kind, n.Detail = "none", "The first hop past your router is a public address; no sign of extra NAT."
		}
		return n
	}
	n.Kind, n.Detail = "unknown", "Couldn't tell: your router doesn't share its internet address and the route didn't reveal the next hop."
	return n
}

// DetectNAT asks the router for its WAN address over UPnP and compares it
// with the public address; if the router won't say, hops (may be nil)
// supplies the route as a weaker second opinion.
func DetectNAT(ctx context.Context, gw, public net.IP, hops func(context.Context) []net.IP) NATInfo {
	if wan, err := RouterWANIP(ctx, gw); err == nil {
		return ClassifyNAT(wan, public)
	}
	if hops != nil {
		n := NATFromHops(gw, hops(ctx))
		n.Public = ipString(public)
		return n
	}
	return NATInfo{Kind: "unknown", Public: ipString(public), Detail: "Couldn't tell: the router doesn't answer UPnP queries."}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// ssdpWait is how long to listen for UPnP answers (shortened in tests).
var ssdpWait = 1500 * time.Millisecond

// ---- UPnP: ask the Internet Gateway Device for its WAN address ----

type upnpService struct {
	Type    string `xml:"serviceType"`
	Control string `xml:"controlURL"`
}

type upnpDevice struct {
	Services []upnpService `xml:"serviceList>service"`
	Devices  []upnpDevice  `xml:"deviceList>device"`
}

type upnpRoot struct {
	URLBase string     `xml:"URLBase"`
	Device  upnpDevice `xml:"device"`
}

func findWANService(d upnpDevice) (upnpService, bool) {
	for _, s := range d.Services {
		if strings.Contains(s.Type, "WANIPConnection") || strings.Contains(s.Type, "WANPPPConnection") {
			return s, true
		}
	}
	for _, c := range d.Devices {
		if s, ok := findWANService(c); ok {
			return s, true
		}
	}
	return upnpService{}, false
}

var extIPRe = regexp.MustCompile(`<NewExternalIPAddress>\s*([^<\s]*)\s*</NewExternalIPAddress>`)

// igd is the router's UPnP WAN connection service.
type igd struct {
	ctl     *url.URL // SOAP control URL, always on the router itself
	svcType string
}

// findIGD locates the gateway's UPnP WAN connection service. It fails when
// the router has UPnP turned off.
func findIGD(ctx context.Context, gw net.IP) (igd, error) {
	rs, err := SSDPSearch(ctx, "urn:schemas-upnp-org:device:InternetGatewayDevice:1", ssdpWait)
	if err != nil {
		return igd{}, err
	}
	var loc *url.URL
	for _, r := range rs {
		u, err := url.Parse(r.Location)
		if err != nil || u.Hostname() == "" {
			continue
		}
		// Only trust a description served by the device that answered, and
		// when we know the gateway, only that device.
		if u.Hostname() != r.From.String() || (gw != nil && !r.From.Equal(gw)) {
			continue
		}
		loc = u
		break
	}
	if loc == nil {
		return igd{}, errors.New("router doesn't offer UPnP")
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	body, _, err := httpGet(c, loc.String(), 256<<10)
	if err != nil {
		return igd{}, err
	}
	var root upnpRoot
	if err := xml.Unmarshal(body, &root); err != nil {
		return igd{}, err
	}
	svc, ok := findWANService(root.Device)
	if !ok {
		return igd{}, errors.New("no WAN connection service")
	}
	base := loc
	if root.URLBase != "" {
		if b, err := url.Parse(root.URLBase); err == nil && b.Hostname() == loc.Hostname() {
			base = b
		}
	}
	ctl, err := base.Parse(svc.Control)
	if err != nil || ctl.Hostname() != loc.Hostname() {
		return igd{}, errors.New("bad control URL")
	}
	return igd{ctl: ctl, svcType: svc.Type}, nil
}

// errSOAPFault is a UPnP error answer, such as "no such entry".
var errSOAPFault = errors.New("upnp fault")

// call sends one SOAP action; args is the inner XML of the request.
func (g igd) call(ctx context.Context, action, args string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	env := `<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:` + action + ` xmlns:u="` + g.svcType + `">` + args + `</u:` + action + `></s:Body></s:Envelope>`
	req, err := http.NewRequestWithContext(c, http.MethodPost, g.ctl.String(), bytes.NewReader([]byte(env)))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", `"`+g.svcType+`#`+action+`"`)
	resp, err := HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(limitBody(resp))
	if resp.StatusCode != http.StatusOK {
		return buf.String(), errSOAPFault
	}
	return buf.String(), nil
}

// RouterWANIP asks the router for its WAN address via UPnP IGD (no
// elevation needed). It fails when the router has UPnP turned off.
func RouterWANIP(ctx context.Context, gw net.IP) (net.IP, error) {
	g, err := findIGD(ctx, gw)
	if err != nil {
		return nil, err
	}
	body, err := g.call(ctx, "GetExternalIPAddress", "")
	if err != nil && !errors.Is(err, errSOAPFault) {
		return nil, err
	}
	m := extIPRe.FindStringSubmatch(body)
	if m == nil {
		return nil, errors.New("router didn't report a WAN address")
	}
	ip := net.ParseIP(m[1])
	if ip == nil || ip.IsUnspecified() {
		return nil, errors.New("router has no WAN address")
	}
	return ip, nil
}
