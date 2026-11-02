package probe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"time"
)

// STUN (RFC 8489): a client asks a server which address and port its
// packets arrive from. Asking two servers from the same socket shows how
// the NAT maps ports, which is what games call the NAT type.

const (
	stunMagic            = 0x2112A442
	stunBindingRequest   = 0x0001
	stunBindingSuccess   = 0x0101
	stunMappedAddress    = 0x0001
	stunXorMappedAddress = 0x0020
)

// stunCookie is stunMagic as bytes, for un-XORing addresses.
var stunCookie = [4]byte{0x21, 0x12, 0xA4, 0x42}

// stunServers are public STUN servers run by different operators, so the
// two answers come from different addresses.
var stunServers = []string{"stun.cloudflare.com:3478", "stun.l.google.com:19302"}

// stunRequest builds a Binding request with transaction ID txid.
func stunRequest(txid [12]byte) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:], stunBindingRequest)
	binary.BigEndian.PutUint32(b[4:], stunMagic)
	copy(b[8:], txid[:])
	return b
}

// parseSTUN reads the mapped address from a Binding success response for
// txid, preferring XOR-MAPPED-ADDRESS (the plain one gets rewritten by some
// routers). Only IPv4 is read.
func parseSTUN(b []byte, txid [12]byte) (*net.UDPAddr, bool) {
	if len(b) < 20 || binary.BigEndian.Uint16(b) != stunBindingSuccess || binary.BigEndian.Uint32(b[4:]) != stunMagic || string(b[8:20]) != string(txid[:]) {
		return nil, false
	}
	end := 20 + int(binary.BigEndian.Uint16(b[2:]))
	if end > len(b) {
		return nil, false
	}
	var plain *net.UDPAddr
	for i := 20; i+4 <= end; {
		typ, n := binary.BigEndian.Uint16(b[i:]), int(binary.BigEndian.Uint16(b[i+2:]))
		v := b[i+4:]
		if i+4+n > end {
			break
		}
		v = v[:n]
		if n >= 8 && v[1] == 1 { // IPv4
			port := int(binary.BigEndian.Uint16(v[2:]))
			ip := net.IP(append([]byte(nil), v[4:8]...))
			switch typ {
			case stunXorMappedAddress:
				port ^= stunMagic >> 16
				for k := range ip {
					ip[k] ^= stunCookie[k]
				}
				return &net.UDPAddr{IP: ip, Port: port}, true
			case stunMappedAddress:
				plain = &net.UDPAddr{IP: ip, Port: port}
			}
		}
		i += 4 + (n+3)&^3 // attributes are padded to 4 bytes
	}
	return plain, plain != nil
}

// stunAsk sends a Binding request from c to server and waits for the
// answer, retrying once: UDP can lose a packet.
func stunAsk(ctx context.Context, c net.PacketConn, server *net.UDPAddr) (*net.UDPAddr, error) {
	var txid [12]byte
	_, _ = rand.Read(txid[:])
	req := stunRequest(txid)
	buf := make([]byte, 1500)
	for _, wait := range []time.Duration{700 * time.Millisecond, 1500 * time.Millisecond} {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := c.WriteTo(req, server); err != nil {
			return nil, err
		}
		_ = c.SetReadDeadline(time.Now().Add(wait))
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				break // this try timed out
			}
			if u, ok := from.(*net.UDPAddr); !ok || !u.IP.Equal(server.IP) {
				continue
			}
			if a, ok := parseSTUN(buf[:n], txid); ok {
				return a, nil
			}
		}
	}
	return nil, errors.New("no answer")
}

// STUNMapping is what one STUN server saw.
type STUNMapping struct {
	Server string `json:"server"`
	Mapped string `json:"mapped,omitempty"` // public ip:port as the server saw it
	Error  string `json:"error,omitempty"`
}

// NATMapping says how the NAT maps this computer's UDP port.
type NATMapping struct {
	Local   string        `json:"local"`
	Answers []STUNMapping `json:"stun"`
	Public  string        `json:"public_ip,omitempty"`
	// Behaviour: "none" (no NAT), "endpoint-independent" (one public port
	// for every destination), "address-dependent" (a new port per
	// destination: symmetric), "udp-blocked" or "unknown".
	Behaviour     string `json:"mapping"`
	PortPreserved bool   `json:"port_preserved"`
}

// localAddrs lists this computer's own IPv4 addresses.
var localAddrs = func() []net.IP {
	var out []net.IP
	as, _ := net.InterfaceAddrs()
	for _, a := range as {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			out = append(out, n.IP)
		}
	}
	return out
}

// DetectNATMapping asks the STUN servers from one UDP socket and compares
// the public address and port each one saw.
func DetectNATMapping(ctx context.Context) NATMapping {
	res := NATMapping{Behaviour: "unknown"}
	c, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		res.Behaviour = "udp-blocked"
		return res
	}
	defer c.Close()
	local := c.LocalAddr().(*net.UDPAddr)
	if ip := LocalIP(); ip != nil {
		res.Local = net.JoinHostPort(ip.String(), strconv.Itoa(local.Port))
	}
	var seen []*net.UDPAddr
	for _, s := range stunServers {
		m := STUNMapping{Server: s}
		addr, err := net.ResolveUDPAddr("udp4", s)
		if err == nil {
			var got *net.UDPAddr
			if got, err = stunAsk(ctx, c, addr); err == nil {
				m.Mapped = got.String()
				seen = append(seen, got)
			}
		}
		if err != nil {
			m.Error = shortErr(err)
		}
		res.Answers = append(res.Answers, m)
	}
	switch {
	case ctx.Err() != nil:
	case len(seen) == 0:
		res.Behaviour = "udp-blocked"
	default:
		res.Public = seen[0].IP.String()
		res.PortPreserved = seen[0].Port == local.Port
		for _, ip := range localAddrs() {
			if ip.Equal(seen[0].IP) {
				res.Behaviour = "none"
				return res
			}
		}
		if len(seen) < 2 {
			break // one answer can't show how ports are mapped
		}
		res.Behaviour = "endpoint-independent"
		for _, a := range seen[1:] {
			if !a.IP.Equal(seen[0].IP) || a.Port != seen[0].Port {
				res.Behaviour = "address-dependent"
			}
		}
	}
	return res
}
