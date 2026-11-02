// Package lanwatch keeps an eye on the local network and says when
// something changes: a device joins or leaves, the router's hardware
// address changes (the classic sign of ARP spoofing), a second DHCP server
// appears, the gateway, DNS servers or public address change, or a device
// opens a port to the internet over UPnP.
package lanwatch

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// Device is one device seen on the network.
type Device struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Name   string `json:"name,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

// Snapshot is the network at one moment.
type Snapshot struct {
	Time       time.Time           `json:"time"`
	Gateway    string              `json:"gateway"`
	GatewayMAC string              `json:"gateway_mac,omitempty"`
	Devices    map[string]Device   `json:"devices"` // by MAC
	DNS        []string            `json:"dns"`
	PublicIP   string              `json:"public_ip,omitempty"`
	Mappings   []probe.PortMapping `json:"port_forwards,omitempty"`
	UPnP       bool                `json:"upnp"`
	DHCP       []string            `json:"dhcp,omitempty"` // server IDs; nil when not checked this round
}

// Event is one change.
type Event struct {
	Time   time.Time `json:"time"`
	Kind   string    `json:"kind"`  // joined, left, spoof, gateway, dns, public-ip, dhcp, upnp-open, upnp-closed
	Level  string    `json:"level"` // info, warn, bad
	Text   string    `json:"text"`
	Detail string    `json:"detail,omitempty"`
}

func label(d Device) string {
	parts := []string{}
	switch {
	case d.Name != "":
		parts = append(parts, d.Name)
	case d.Vendor != "":
		parts = append(parts, d.Vendor)
	}
	parts = append(parts, d.IP)
	if len(parts) == 1 {
		return parts[0]
	}
	return parts[0] + " (" + parts[1] + ")"
}

func mapKey(m probe.PortMapping) string {
	return fmt.Sprintf("%s/%d", strings.ToUpper(m.Protocol), m.ExternalPort)
}

// Diff compares two snapshots. known lists MACs seen before this run
// (from the devices list), so a joining device can be called new.
// gone holds MACs missing since when; a device counts as left only after
// leaveAfter, since phones sleep and ARP entries come and go.
func Diff(prev, cur Snapshot, known map[string]bool, gone map[string]time.Time, leaveAfter time.Duration) []Event {
	var evs []Event
	add := func(kind, level, text, detail string) {
		evs = append(evs, Event{Time: cur.Time, Kind: kind, Level: level, Text: text, Detail: detail})
	}
	// The router's hardware address: if it changes while its IP stays,
	// another machine may be answering for it.
	switch {
	case prev.Gateway != cur.Gateway && cur.Gateway != "":
		add("gateway", "warn", fmt.Sprintf("The default gateway changed from %s to %s", prev.Gateway, cur.Gateway),
			"a new router, another network, or a device pretending to be the router")
	case prev.GatewayMAC != "" && cur.GatewayMAC != "" && prev.GatewayMAC != cur.GatewayMAC:
		add("spoof", "bad", fmt.Sprintf("The router's hardware address changed: %s is now %s, was %s", cur.Gateway, cur.GatewayMAC, prev.GatewayMAC),
			"if the router wasn't replaced, another device may be impersonating it to read your traffic (ARP spoofing)")
	}
	// Another IP answering with the router's MAC.
	if cur.GatewayMAC != "" {
		for _, d := range cur.Devices {
			if d.MAC == cur.GatewayMAC && d.IP != cur.Gateway {
				if old, ok := prev.Devices[d.MAC]; !ok || old.IP == cur.Gateway || old.IP != d.IP {
					add("spoof", "warn", fmt.Sprintf("%s answers with the router's hardware address", d.IP), "routers can have several addresses; if this isn't one of them, something is spoofing")
				}
			}
		}
	}
	for mac, d := range cur.Devices {
		delete(gone, mac)
		if _, ok := prev.Devices[mac]; ok || mac == cur.GatewayMAC {
			continue
		}
		if known != nil && !known[mac] {
			add("joined", "warn", "New device: "+label(d), mac)
			known[mac] = true
		} else {
			add("joined", "info", "Joined: "+label(d), mac)
		}
	}
	for mac, d := range prev.Devices {
		if _, ok := cur.Devices[mac]; ok || mac == prev.GatewayMAC {
			continue
		}
		since, ok := gone[mac]
		if !ok {
			gone[mac] = cur.Time
			cur.Devices[mac] = d // keep it until it has been gone long enough
			continue
		}
		if cur.Time.Sub(since) < leaveAfter {
			cur.Devices[mac] = d
			continue
		}
		delete(gone, mac)
		add("left", "info", "Left: "+label(d), mac)
	}
	if len(prev.DNS) > 0 && len(cur.DNS) > 0 && strings.Join(prev.DNS, ",") != strings.Join(cur.DNS, ",") {
		add("dns", "warn", fmt.Sprintf("The DNS servers changed: %s, were %s", strings.Join(cur.DNS, ", "), strings.Join(prev.DNS, ", ")),
			"expected after switching networks or VPNs; otherwise something may be redirecting name lookups")
	}
	if prev.PublicIP != "" && cur.PublicIP != "" && prev.PublicIP != cur.PublicIP {
		add("public-ip", "info", fmt.Sprintf("The public address changed: %s, was %s", cur.PublicIP, prev.PublicIP), "the ISP gave the line a new address")
	}
	if len(cur.DHCP) > 1 && (len(prev.DHCP) <= 1 || strings.Join(prev.DHCP, ",") != strings.Join(cur.DHCP, ",")) {
		add("dhcp", "bad", fmt.Sprintf("%d DHCP servers answer: %s", len(cur.DHCP), strings.Join(cur.DHCP, ", ")),
			"only one should; a second hands out its own settings, by mistake or to redirect traffic")
	}
	if cur.UPnP || prev.UPnP {
		was := map[string]probe.PortMapping{}
		for _, m := range prev.Mappings {
			was[mapKey(m)] = m
		}
		now := map[string]bool{}
		for _, m := range cur.Mappings {
			now[mapKey(m)] = true
			if _, ok := was[mapKey(m)]; !ok && prev.UPnP {
				d := m.Description
				if d == "" {
					d = "no description"
				}
				add("upnp-open", "warn", fmt.Sprintf("%s opened %s port %d to the internet", m.Client, strings.ToUpper(m.Protocol), m.ExternalPort), d)
			}
		}
		for k, m := range was {
			if !now[k] && cur.UPnP {
				add("upnp-closed", "info", fmt.Sprintf("%s closed %s port %d", m.Client, strings.ToUpper(m.Protocol), m.ExternalPort), "")
			}
		}
	}
	order := map[string]int{"bad": 0, "warn": 1, "info": 2}
	sort.SliceStable(evs, func(i, j int) bool { return order[evs[i].Level] < order[evs[j].Level] })
	return evs
}

// Test seams: how a snapshot is taken.
var (
	gatewayIP = probe.DefaultGateway
	localIP   = probe.LocalIP
	subnetOf  = probe.LocalSubnet
	discover  = probe.DiscoverDevices
	arpTable  = probe.ARPTable
	dnsList   = probe.DNSServers
	publicIP  = probe.PublicIP
	mappings  = probe.PortMappings
	findDHCP  = probe.FindDHCPServers
)

// Take looks at the network once. withDHCP asks for DHCP servers too
// (slower, and the answer may need admin rights).
func Take(ctx context.Context, withDHCP bool) (Snapshot, error) {
	s := Snapshot{Time: time.Now(), Devices: map[string]Device{}}
	gw, err := gatewayIP()
	if err != nil {
		return s, fmt.Errorf("no router found")
	}
	s.Gateway = gw.String()
	me := localIP()
	subnet, err := subnetOf(me)
	if err != nil {
		return s, err
	}
	res := discover(ctx, me, gw, subnet, probe.ScanOptions{MDNSWait: time.Second, SSDPWait: time.Second})
	for _, d := range res.Devices {
		if d.MAC == "" || d.Self {
			continue
		}
		mac := strings.ToLower(d.MAC)
		s.Devices[mac] = Device{IP: d.IP, MAC: mac, Name: d.Name, Vendor: d.Vendor}
		if d.Gateway {
			s.GatewayMAC = mac
		}
	}
	// The ARP table has the last word on the router's MAC.
	for _, e := range arpTable(ctx) {
		if e.IP.Equal(gw) {
			s.GatewayMAC = strings.ToLower(e.MAC)
		}
	}
	dns := dnsList(ctx)
	s.DNS = append([]string(nil), dns...)
	sort.Strings(s.DNS)
	if ip, err := publicIP(ctx); err == nil && ip != nil {
		s.PublicIP = ip.String()
	}
	if m, err := mappings(ctx, gw); err == nil {
		s.UPnP, s.Mappings = true, m
	}
	if withDHCP {
		r := findDHCP(ctx, 3*time.Second)
		if r.Unavailable == "" {
			s.DHCP = []string{}
			for _, sv := range r.Servers {
				s.DHCP = append(s.DHCP, sv.ServerID)
			}
			sort.Strings(s.DHCP)
		}
	}
	return s, nil
}

// Own reports whether the network is private (lanwatch watches only
// those).
func Own(gw net.IP) bool { return gw != nil && (gw.IsPrivate() || gw.IsLinkLocalUnicast()) }
