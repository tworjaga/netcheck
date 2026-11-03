// Package wol sends Wake-on-LAN magic packets.
package wol

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

// ParseMAC reads "aa:bb:cc:dd:ee:ff", "aa-bb-...", "aabb.ccdd.eeff" or
// "aabbccddeeff".
func ParseMAC(s string) (net.HardwareAddr, error) {
	s = strings.TrimSpace(s)
	if len(s) == 12 {
		if b, err := hex.DecodeString(s); err == nil {
			return net.HardwareAddr(b), nil
		}
	}
	m, err := net.ParseMAC(s)
	if err != nil || len(m) != 6 {
		return nil, fmt.Errorf("%q isn't a MAC address (like 00:11:22:33:44:55)", s)
	}
	return m, nil
}

// Packet is the magic packet: six 0xFF bytes, then the MAC 16 times.
func Packet(mac net.HardwareAddr) []byte {
	b := make([]byte, 0, 102)
	for i := 0; i < 6; i++ {
		b = append(b, 0xff)
	}
	for i := 0; i < 16; i++ {
		b = append(b, mac...)
	}
	return b
}

// Broadcasts lists where to send: the limited broadcast, and each IPv4
// network's own broadcast address (some routers and Windows only pass the
// directed one out of the right interface).
func Broadcasts(nets []*net.IPNet) []string {
	out := []string{"255.255.255.255"}
	seen := map[string]bool{out[0]: true}
	for _, n := range nets {
		ip4 := n.IP.To4()
		if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || len(n.Mask) != 4 {
			continue
		}
		b := make(net.IP, 4)
		for i := range b {
			b[i] = ip4[i] | ^n.Mask[i]
		}
		if !seen[b.String()] {
			seen[b.String()] = true
			out = append(out, b.String())
		}
	}
	return out
}

// LocalNets are this machine's IPv4 networks.
func LocalNets() []*net.IPNet {
	var out []*net.IPNet
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			out = append(out, &net.IPNet{IP: n.IP.To4(), Mask: n.Mask[len(n.Mask)-4:]})
		}
	}
	return out
}

// send is a test seam.
var send = func(addr string, b []byte) error {
	c, err := net.Dial("udp4", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(b)
	return err
}

// Wake sends the packet to every target address on port, three times each
// (it's UDP: a lost packet is a machine that stays asleep). It returns the
// addresses it reached and the errors from the rest.
func Wake(mac net.HardwareAddr, targets []string, port int) ([]string, []error) {
	b := Packet(mac)
	var ok []string
	var errs []error
	for _, t := range targets {
		var err error
		for i := 0; i < 3; i++ {
			if e := send(net.JoinHostPort(t, fmt.Sprint(port)), b); e != nil {
				err = e
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t, err))
		} else {
			ok = append(ok, t)
		}
	}
	return ok, errs
}
