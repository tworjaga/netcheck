package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// DHCPServer is one server that answered a DHCPDISCOVER.
type DHCPServer struct {
	ServerID string   `json:"server_id"`            // option 54, else the sender
	Offered  string   `json:"offered_ip,omitempty"` // the address it would lease
	Router   string   `json:"router,omitempty"`     // option 3
	DNS      []string `json:"dns,omitempty"`        // option 6
}

// DHCPResult lists every DHCP server that offered an address.
type DHCPResult struct {
	Servers []DHCPServer `json:"servers"`
	// Unavailable is set when the DHCP client port couldn't be opened:
	// it needs administrator rights, or the system's DHCP client holds it.
	Unavailable string `json:"unavailable,omitempty"`
	Error       string `json:"error,omitempty"`
}

var dhcpMagic = []byte{99, 130, 83, 99}

// buildDiscover makes a DHCPDISCOVER with the broadcast flag set, so
// servers answer to 255.255.255.255 rather than an address we don't have.
func buildDiscover(xid uint32, mac net.HardwareAddr) []byte {
	p := make([]byte, 240, 300)
	p[0], p[1], p[2] = 1, 1, 6 // BOOTREQUEST, Ethernet, 6-byte MAC
	binary.BigEndian.PutUint32(p[4:], xid)
	binary.BigEndian.PutUint16(p[10:], 0x8000) // broadcast flag
	copy(p[28:], mac)
	copy(p[236:], dhcpMagic)
	p = append(p, 53, 1, 1)       // DHCP message type: DISCOVER
	p = append(p, 55, 3, 1, 3, 6) // ask for subnet, router, DNS
	p = append(p, 61, 7, 1)       // client identifier: type 1 + MAC
	p = append(p, mac[:6]...)
	return append(p, 255)
}

// parseOffer reads a DHCPOFFER for xid. ok is false for anything else.
func parseOffer(b []byte, xid uint32, from net.IP) (DHCPServer, bool) {
	if len(b) < 240 || b[0] != 2 || binary.BigEndian.Uint32(b[4:]) != xid || string(b[236:240]) != string(dhcpMagic) {
		return DHCPServer{}, false
	}
	s := DHCPServer{Offered: net.IP(b[16:20]).String()}
	msgType := 0
	for i := 240; i < len(b); {
		code := b[i]
		if code == 255 {
			break
		}
		if code == 0 {
			i++
			continue
		}
		if i+1 >= len(b) || i+2+int(b[i+1]) > len(b) {
			break
		}
		v := b[i+2 : i+2+int(b[i+1])]
		switch code {
		case 53:
			if len(v) == 1 {
				msgType = int(v[0])
			}
		case 54:
			if len(v) == 4 {
				s.ServerID = net.IP(v).String()
			}
		case 3:
			if len(v) >= 4 {
				s.Router = net.IP(v[:4]).String()
			}
		case 6:
			for j := 0; j+4 <= len(v); j += 4 {
				s.DNS = append(s.DNS, net.IP(v[j:j+4]).String())
			}
		}
		i += 2 + len(v)
	}
	if msgType != 2 { // OFFER
		return DHCPServer{}, false
	}
	if s.ServerID == "" && from != nil {
		s.ServerID = from.String()
	}
	return s, true
}

// errNeedsElevation is reported when port 68 can't be bound.
var errNeedsElevation = errors.New("port 68 unavailable")

// dhcpExchange is a test seam: broadcast pkt from port 68 and collect
// every datagram that arrives within wait.
var dhcpExchange = func(ctx context.Context, pkt []byte, wait time.Duration) ([]dhcpReply, error) {
	c, err := net.ListenPacket("udp4", ":68")
	if err != nil {
		// EACCES/EPERM without root on Unix, EADDRINUSE (or Windows' own
		// WSAEACCES) when the system DHCP client holds the port. Every bind
		// failure here comes down to one of those.
		return nil, errNeedsElevation
	}
	defer c.Close()
	if _, err := c.WriteTo(pkt, &net.UDPAddr{IP: net.IPv4bcast, Port: 67}); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = c.SetReadDeadline(deadline)
	var out []dhcpReply
	buf := make([]byte, 1500)
	for ctx.Err() == nil {
		n, addr, err := c.ReadFrom(buf)
		if err != nil {
			break // deadline reached
		}
		var from net.IP
		if u, ok := addr.(*net.UDPAddr); ok {
			from = u.IP
		}
		out = append(out, dhcpReply{append([]byte(nil), buf[:n]...), from})
	}
	return out, nil
}

type dhcpReply struct {
	b    []byte
	from net.IP
}

// hardwareAddr finds the MAC of the interface carrying the default route,
// or makes up a locally administered one.
func hardwareAddr() net.HardwareAddr {
	if local := LocalIP(); local != nil {
		ifs, _ := net.Interfaces()
		for _, i := range ifs {
			addrs, _ := i.Addrs()
			for _, a := range addrs {
				if n, ok := a.(*net.IPNet); ok && n.IP.Equal(local) && len(i.HardwareAddr) == 6 {
					return i.HardwareAddr
				}
			}
		}
	}
	m := make(net.HardwareAddr, 6)
	_, _ = rand.Read(m)
	m[0] = m[0]&0xfe | 0x02
	return m
}

// FindDHCPServers broadcasts one DHCPDISCOVER and lists the servers that
// offer an address. Nothing is accepted, so no lease is taken.
func FindDHCPServers(ctx context.Context, wait time.Duration) DHCPResult {
	res := DHCPResult{Servers: []DHCPServer{}}
	var xb [4]byte
	_, _ = rand.Read(xb[:])
	xid := binary.BigEndian.Uint32(xb[:])
	replies, err := dhcpExchange(ctx, buildDiscover(xid, hardwareAddr()), wait)
	switch {
	case errors.Is(err, errNeedsElevation):
		res.Unavailable = "needs administrator rights (or the system's DHCP client is using port 68)"
		return res
	case err != nil:
		res.Error = shortErr(err)
		return res
	}
	seen := map[string]bool{}
	for _, r := range replies {
		if s, ok := parseOffer(r.b, xid, r.from); ok && !seen[s.ServerID] {
			seen[s.ServerID] = true
			res.Servers = append(res.Servers, s)
		}
	}
	return res
}
