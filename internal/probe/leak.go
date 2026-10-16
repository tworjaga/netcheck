package probe

import (
	"context"
	"net"
	"regexp"
	"strings"
	"time"
)

// Resolver egress: the address a DNS server uses when it goes out to the
// internet to look a name up. Two public "who's asking?" names reveal it:
// Akamai's answers with the resolver's address as an A record, Google's as
// a TXT record. Neither needs anything but the system resolver.
var (
	whoamiAkamai = "whoami.akamai.net"
	whoamiGoogle = "o-o.myaddr.l.google.com"
)

// lookupHostIPs is a test seam for A lookups via the system resolver.
var lookupHostIPs = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip4", host)
}

// listInterfaces is a test seam: up interfaces with an address.
var listInterfaces = func() []NetIf {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []NetIf
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		// macOS keeps several utun interfaces up for system services with
		// only link-local addresses; a tunnel carrying traffic has a real one.
		addrs, _ := i.Addrs()
		usable := false
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && (n.IP.To4() != nil || n.IP.IsGlobalUnicast()) && !n.IP.IsLinkLocalUnicast() {
				usable = true
			}
		}
		if !usable {
			continue
		}
		out = append(out, NetIf{Name: i.Name, PointToPoint: i.Flags&net.FlagPointToPoint != 0})
	}
	return out
}

// NetIf is the little we need to know about a network interface.
type NetIf struct {
	Name         string
	PointToPoint bool
}

// Interface names VPN clients use: tun/tap/wg/utun/ppp on Unix, and the
// adapter names Windows shows for common VPN products. Mesh overlays such as
// Tailscale and ZeroTier are left out: they don't carry all your traffic.
var vpnName = regexp.MustCompile(`(?i)^(tun|tap|wg|utun|ppp|ipsec|gpd|nordlynx|proton|mullvad)|wireguard|openvpn|vpn|tap-windows|wintun|anyconnect|globalprotect|fortinet|pangp|juniper`)

// VPNInterfaces lists interfaces that look like VPN tunnels.
func VPNInterfaces() []string {
	var out []string
	for _, i := range listInterfaces() {
		if vpnName.MatchString(i.Name) {
			out = append(out, i.Name)
		}
	}
	return out
}

// Egress is one resolver address the internet saw, with its owner.
type Egress struct {
	IP  string `json:"ip"`
	ASN string `json:"asn,omitempty"`
	Org string `json:"org,omitempty"`
}

// LeakResult is everything the leak check found.
type LeakResult struct {
	VPN       []string `json:"vpn_interfaces"`
	Public    IPInfo   `json:"public"`
	Resolvers []Egress `json:"resolvers"`
	Error     string   `json:"error,omitempty"`
}

var reIP = regexp.MustCompile(`[0-9a-fA-F:.]{7,}`)

func resolverEgress(ctx context.Context) []net.IP {
	seen := map[string]bool{}
	var out []net.IP
	add := func(ip net.IP) {
		if ip != nil && !seen[ip.String()] {
			seen[ip.String()] = true
			out = append(out, ip)
		}
	}
	// Several lookups: a resolver may be a pool that leaves from many addresses.
	for i := 0; i < 2; i++ {
		c, cancel := context.WithTimeout(ctx, 3*time.Second)
		if ips, err := lookupHostIPs(c, whoamiAkamai); err == nil {
			for _, ip := range ips {
				add(ip)
			}
		}
		if txt, err := txtLookup(c, whoamiGoogle); err == nil {
			for _, t := range txt {
				// "edns0-client-subnet …" records name the client, not the resolver.
				if strings.HasPrefix(t, "edns0") {
					continue
				}
				add(net.ParseIP(reIP.FindString(t)))
			}
		}
		cancel()
	}
	return out
}

// CheckLeak finds which resolvers answer for this machine and who owns
// them, and compares that with the public address and any VPN.
func CheckLeak(ctx context.Context) LeakResult {
	res := LeakResult{VPN: VPNInterfaces(), Resolvers: []Egress{}}
	pubDone := make(chan struct{})
	go func() {
		res.Public = GetIPInfo(ctx)
		close(pubDone)
	}()
	ips := resolverEgress(ctx)
	if len(ips) == 0 {
		res.Error = "couldn't see which DNS servers answer for you"
	}
	res.Resolvers = make([]Egress, len(ips))
	done := make(chan struct{}, len(ips))
	for i, ip := range ips {
		go func() {
			info := LookupASN(ctx, ip)
			res.Resolvers[i] = Egress{IP: ip.String(), ASN: info.ASN, Org: info.ISP}
			done <- struct{}{}
		}()
	}
	for range ips {
		<-done
	}
	<-pubDone
	return res
}
