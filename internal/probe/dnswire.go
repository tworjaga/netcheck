package probe

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
	"strings"
)

// A deliberately small DNS wire codec: enough to build queries and read A,
// AAAA, PTR, TXT and SRV answers. It backs mDNS, DNSSEC and leak checks,
// which the standard resolver can't express (flags, raw TXT, multicast).

// DNS record types and header flag bits used here.
const (
	TypeA    = 1
	TypePTR  = 12
	TypeTXT  = 16
	TypeAAAA = 28
	TypeSRV  = 33
	TypeOPT  = 41

	flagQR = 0x8000
	flagRD = 0x0100
	flagAD = 0x0020
)

// RR is one resource record.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	IP    net.IP   // A / AAAA
	Host  string   // PTR / SRV target
	Text  []string // TXT strings
	Port  uint16   // SRV
}

// DNSMsg is a parsed DNS message.
type DNSMsg struct {
	ID        uint16
	Response  bool
	AD        bool // answer was DNSSEC-validated by the resolver
	RCode     int
	Questions []string
	Answers   []RR // answers + authority + additional, flattened
}

func appendName(b []byte, name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) > 63 {
				label = label[:63]
			}
			b = append(b, byte(len(label)))
			b = append(b, label...)
		}
	}
	return append(b, 0)
}

// BuildQuery makes a one-question query. With do set it adds an EDNS0 OPT
// record asking for DNSSEC data.
func BuildQuery(id uint16, name string, qtype uint16, rd, do bool) []byte {
	flags := uint16(0)
	if rd {
		flags |= flagRD
	}
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[0:], id)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	if do {
		binary.BigEndian.PutUint16(b[10:], 1)
	}
	b = appendName(b, name)
	b = binary.BigEndian.AppendUint16(b, qtype)
	b = binary.BigEndian.AppendUint16(b, 1) // IN
	if do {
		b = append(b, 0)                              // root name
		b = binary.BigEndian.AppendUint16(b, TypeOPT) // type
		b = binary.BigEndian.AppendUint16(b, 1232)    // UDP payload size
		b = append(b, 0, 0, 0x80, 0)                  // ext rcode, version, DO flag
		b = binary.BigEndian.AppendUint16(b, 0)       // rdlength
	}
	return b
}

func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next, jumped := -1, false
	for hops := 0; hops < 64; hops++ {
		if off >= len(msg) {
			return "", 0, errors.New("dns: truncated name")
		}
		l := int(msg[off])
		switch {
		case l == 0:
			if !jumped {
				next = off + 1
			}
			return strings.Join(labels, ".") + ".", next, nil
		case l&0xC0 == 0xC0:
			if off+1 >= len(msg) {
				return "", 0, errors.New("dns: truncated pointer")
			}
			if !jumped {
				next = off + 2
			}
			off = (l&0x3F)<<8 | int(msg[off+1])
			jumped = true
		default:
			if off+1+l > len(msg) {
				return "", 0, errors.New("dns: truncated label")
			}
			labels = append(labels, string(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, errors.New("dns: name too deep")
}

// ParseMsg decodes a DNS message.
func ParseMsg(b []byte) (*DNSMsg, error) {
	if len(b) < 12 {
		return nil, errors.New("dns: short message")
	}
	m := &DNSMsg{ID: binary.BigEndian.Uint16(b)}
	flags := binary.BigEndian.Uint16(b[2:])
	m.Response = flags&flagQR != 0
	m.AD = flags&flagAD != 0
	m.RCode = int(flags & 0x0F)
	qd, an := int(binary.BigEndian.Uint16(b[4:])), int(binary.BigEndian.Uint16(b[6:]))
	ns, ar := int(binary.BigEndian.Uint16(b[8:])), int(binary.BigEndian.Uint16(b[10:]))
	off := 12
	for i := 0; i < qd; i++ {
		name, n, err := readName(b, off)
		if err != nil || n+4 > len(b) {
			return nil, errors.New("dns: bad question")
		}
		m.Questions = append(m.Questions, name)
		off = n + 4
	}
	for i := 0; i < an+ns+ar; i++ {
		name, n, err := readName(b, off)
		if err != nil || n+10 > len(b) {
			return m, nil // keep what parsed so far
		}
		rr := RR{Name: name, Type: binary.BigEndian.Uint16(b[n:]), Class: binary.BigEndian.Uint16(b[n+2:]) & 0x7FFF, TTL: binary.BigEndian.Uint32(b[n+4:])}
		rdlen := int(binary.BigEndian.Uint16(b[n+8:]))
		start := n + 10
		if start+rdlen > len(b) {
			return m, nil
		}
		rd := b[start : start+rdlen]
		switch rr.Type {
		case TypeA:
			if rdlen == 4 {
				rr.IP = net.IP(append([]byte(nil), rd...))
			}
		case TypeAAAA:
			if rdlen == 16 {
				rr.IP = net.IP(append([]byte(nil), rd...))
			}
		case TypePTR:
			rr.Host, _, _ = readName(b, start)
		case TypeSRV:
			if rdlen > 6 {
				rr.Port = binary.BigEndian.Uint16(rd[4:])
				rr.Host, _, _ = readName(b, start+6)
			}
		case TypeTXT:
			for i := 0; i < len(rd); {
				l := int(rd[i])
				if i+1+l > len(rd) {
					break
				}
				rr.Text = append(rr.Text, string(rd[i+1:i+1+l]))
				i += 1 + l
			}
		}
		if rr.Type != TypeOPT {
			m.Answers = append(m.Answers, rr)
		}
		off = start + rdlen
	}
	return m, nil
}

// ReverseName returns the in-addr.arpa name for an IPv4 address.
func ReverseName(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return strconv.Itoa(int(v4[3])) + "." + strconv.Itoa(int(v4[2])) + "." + strconv.Itoa(int(v4[1])) + "." + strconv.Itoa(int(v4[0])) + ".in-addr.arpa."
}
