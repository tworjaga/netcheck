package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device is one thing found on the local network.
type Device struct {
	IP        string   `json:"ip"`
	MAC       string   `json:"mac,omitempty"`
	Vendor    string   `json:"vendor,omitempty"`
	RandomMAC bool     `json:"random_mac,omitempty"` // privacy address: vendor unknown by design
	Name      string   `json:"name,omitempty"`
	Kind      string   `json:"kind,omitempty"`
	Services  []string `json:"services,omitempty"`
	Server    string   `json:"upnp_server,omitempty"`
	RTTMs     float64  `json:"rtt_ms,omitempty"`
	Gateway   bool     `json:"gateway,omitempty"`
	Self      bool     `json:"self,omitempty"`
	Seen      []string `json:"seen_via"` // icmp, arp, mdns, ssdp
}

// DevicesResult is the outcome of a LAN scan.
type DevicesResult struct {
	Subnet  string   `json:"subnet"`
	Devices []Device `json:"devices"`
	Note    string   `json:"note,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// maxSweepHosts caps how many addresses are probed; bigger networks are
// narrowed to the /24 around this machine.
const maxSweepHosts = 1024

// LocalSubnet finds the IPv4 network this machine uses to reach the internet.
func LocalSubnet(local net.IP) (*net.IPNet, error) {
	if local == nil {
		return nil, errors.New("no local address")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.Equal(local) && ipn.IP.To4() != nil {
				return narrowSubnet(ipn), nil
			}
		}
	}
	return narrowSubnet(&net.IPNet{IP: local, Mask: net.CIDRMask(24, 32)}), nil
}

func narrowSubnet(n *net.IPNet) *net.IPNet {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return n
	}
	if ones < 22 {
		ones = 24
	}
	m := net.CIDRMask(ones, 32)
	return &net.IPNet{IP: n.IP.To4().Mask(m), Mask: m}
}

// Hosts lists the usable host addresses of n (no network or broadcast).
func Hosts(n *net.IPNet) []net.IP {
	ones, bits := n.Mask.Size()
	if bits != 32 {
		return nil
	}
	base := n.IP.To4()
	if base == nil {
		return nil
	}
	size := 1 << (32 - ones)
	if size > maxSweepHosts {
		size = maxSweepHosts
	}
	start := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	var out []net.IP
	for i := 1; i < size-1 || (size <= 2 && i < size); i++ {
		v := start + uint32(i)
		out = append(out, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).To4())
	}
	return out
}

// pokeUDP nudges the OS into resolving each address with ARP by sending a
// tiny datagram. It needs no privileges and works even for hosts that ignore
// ping, which is why the sweep does it before reading the ARP table.
var pokeUDP = func(ctx context.Context, ips []net.IP) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, 128)
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 9})
			if err != nil {
				return
			}
			_ = c.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
			_, _ = c.Write([]byte{0})
			c.Close()
		}(ip)
	}
	wg.Wait()
}

// sweepICMP pings every address and returns the round-trip time of those
// that answered. It returns nil when ICMP can't be used.
func sweepICMP(ctx context.Context, ips []net.IP, onFound func(net.IP)) map[string]float64 {
	e, err := openEchoer()
	if err != nil {
		return nil
	}
	var mu sync.Mutex
	found := map[string]float64{}
	sem := make(chan struct{}, 64)
	var wg sync.WaitGroup
	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			defer func() { <-sem }()
			if r, err := e.Echo(ip, EchoOpts{Timeout: 500 * time.Millisecond}); err == nil && r.Kind == EchoOK {
				mu.Lock()
				found[ip.String()] = float64(r.RTT.Microseconds()) / 1000
				mu.Unlock()
				if onFound != nil {
					onFound(ip)
				}
			}
		}(ip)
	}
	wg.Wait()
	return found
}

// reverseLookup asks the system resolver (usually the router) for a name.
var reverseLookup = func(ctx context.Context, ip string) string {
	c, cancel := context.WithTimeout(ctx, 700*time.Millisecond)
	defer cancel()
	names, err := net.DefaultResolver.LookupAddr(c, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.ToLower(strings.TrimSuffix(names[0], "."))
}

// guessKind makes a short human label from what a device advertises.
func guessKind(d *Device) string {
	has := func(want ...string) bool {
		for _, s := range d.Services {
			for _, w := range want {
				if s == w {
					return true
				}
			}
		}
		return false
	}
	srv := strings.ToLower(d.Server)
	switch {
	case d.Gateway:
		return "router"
	case has("googlecast"):
		return "Chromecast / Google speaker"
	case has("ipp", "printer", "pdl-datastream"):
		return "printer"
	case has("airplay", "raop", "companion-link", "homekit", "hap"):
		return "Apple / HomeKit device"
	case has("spotify-connect"):
		return "speaker"
	case strings.Contains(srv, "sonos"):
		return "Sonos speaker"
	case strings.Contains(srv, "roku"):
		return "Roku"
	case strings.Contains(srv, "synology"), d.Vendor == "Synology", d.Vendor == "QNAP":
		return "NAS"
	case d.Vendor == "Raspberry Pi":
		return "Raspberry Pi"
	case d.Vendor == "Espressif":
		return "smart-home gadget"
	case has("smb", "afpovertcp"):
		return "file-sharing computer"
	case has("workstation", "ssh"):
		return "computer"
	}
	return ""
}

// ScanOptions lets callers (and tests) adjust a scan.
type ScanOptions struct {
	MDNSWait time.Duration
	SSDPWait time.Duration
	OnStatus func(phase string) // "sweeping", "arp", "names", "mdns", "ssdp"
	OnFound  func(count int)    // live count of devices seen so far
}

// DiscoverDevices finds devices on the local subnet with a ping sweep, the
// ARP table, mDNS and SSDP. Nothing here needs administrator rights.
func DiscoverDevices(ctx context.Context, local, gateway net.IP, subnet *net.IPNet, o ScanOptions) DevicesResult {
	res := DevicesResult{Subnet: subnet.String()}
	if o.MDNSWait == 0 {
		o.MDNSWait = 1800 * time.Millisecond
	}
	if o.SSDPWait == 0 {
		o.SSDPWait = 1800 * time.Millisecond
	}
	status := func(s string) {
		if o.OnStatus != nil {
			o.OnStatus(s)
		}
	}
	devs := map[string]*Device{}
	var mu sync.Mutex
	touch := func(ip net.IP, via string) *Device {
		if ip == nil || !subnet.Contains(ip) {
			return nil
		}
		k := ip.String()
		mu.Lock()
		defer mu.Unlock()
		d := devs[k]
		if d == nil {
			d = &Device{IP: k}
			devs[k] = d
			if o.OnFound != nil {
				o.OnFound(len(devs))
			}
		}
		for _, s := range d.Seen {
			if s == via {
				return d
			}
		}
		d.Seen = append(d.Seen, via)
		return d
	}

	hosts := Hosts(subnet)
	if len(hosts) == 0 {
		res.Error = "couldn't work out which addresses to scan"
		return res
	}

	// Phase 1: sweep. ICMP, the UDP nudge and mDNS/SSDP all run together.
	status("sweeping")
	var wg sync.WaitGroup
	var rtts map[string]float64
	icmpUsed := false
	wg.Add(1)
	go func() {
		defer wg.Done()
		rtts = sweepICMP(ctx, hosts, func(ip net.IP) { touch(ip, "icmp") })
		icmpUsed = rtts != nil
	}()
	wg.Add(1)
	go func() { defer wg.Done(); pokeUDP(ctx, hosts) }()

	var mdns []MDNSDevice
	var ssdp []SSDPResponse
	wg.Add(2)
	go func() { defer wg.Done(); mdns = MDNSScan(ctx, o.MDNSWait) }()
	go func() {
		defer wg.Done()
		ssdp, _ = SSDPSearch(ctx, "ssdp:all", o.SSDPWait)
	}()
	wg.Wait()
	if ctx.Err() != nil {
		res.Error = "interrupted"
		return res
	}
	if !icmpUsed {
		res.Note = "ping isn't available without elevation here; devices were found through ARP, mDNS and SSDP instead"
	}

	// Phase 2: the neighbour table now holds everything that answered ARP.
	status("arp")
	for _, e := range readARP(ctx) {
		if d := touch(e.IP, "arp"); d != nil {
			d.MAC = e.MAC
		}
	}
	for _, m := range mdns {
		if d := touch(m.IP, "mdns"); d != nil {
			d.Services = append(d.Services, m.Services...)
			if d.Name == "" {
				d.Name = m.Hostname
			}
		}
	}
	for _, s := range ssdp {
		if d := touch(s.From, "ssdp"); d != nil && d.Server == "" {
			d.Server = s.Server
		}
	}
	if local != nil {
		if d := touch(local, "self"); d != nil {
			d.Self = true
		}
	}
	if gateway != nil {
		if d := touch(gateway, "gateway"); d != nil {
			d.Gateway = true
		}
	}

	// Phase 3: names from the router's DNS for anything still unnamed.
	status("names")
	var nw sync.WaitGroup
	sem := make(chan struct{}, 32)
	mu.Lock()
	list := make([]*Device, 0, len(devs))
	for _, d := range devs {
		list = append(list, d)
	}
	mu.Unlock()
	for _, d := range list {
		if d.Name != "" || ctx.Err() != nil {
			continue
		}
		sem <- struct{}{}
		nw.Add(1)
		go func(d *Device) {
			defer nw.Done()
			defer func() { <-sem }()
			d.Name = reverseLookup(ctx, d.IP)
		}(d)
	}
	nw.Wait()

	for _, d := range list {
		if d.MAC != "" {
			d.Vendor = Vendor(d.MAC)
			d.RandomMAC = IsRandomMAC(d.MAC)
		}
		if ms, ok := rtts[d.IP]; ok {
			d.RTTMs = ms
		}
		sort.Strings(d.Services)
		d.Services = dedupe(d.Services)
		d.Kind = guessKind(d)
		res.Devices = append(res.Devices, *d)
	}
	sort.Slice(res.Devices, func(i, j int) bool { return ipLess(res.Devices[i].IP, res.Devices[j].IP) })
	return res
}

func ipLess(a, b string) bool {
	x, y := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if x == nil || y == nil {
		return a < b
	}
	return string(x) < string(y)
}

// Summary is a one-line description such as "12 devices on 192.168.1.0/24".
func (r DevicesResult) Summary() string {
	n := len(r.Devices)
	word := "devices"
	if n == 1 {
		word = "device"
	}
	return fmt.Sprintf("%d %s on %s", n, word, r.Subnet)
}
