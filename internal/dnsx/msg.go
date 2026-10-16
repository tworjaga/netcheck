package dnsx

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Question is what a query asks.
type Question struct {
	Name  string `json:"name"`
	Type  uint16 `json:"-"`
	Class uint16 `json:"-"`
}

// RR is one resource record: its header, the record data in standard
// presentation format, and the raw data for anything that needs more.
type RR struct {
	Name  string `json:"name"`
	Type  uint16 `json:"-"`
	Class uint16 `json:"-"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
	Raw   []byte `json:"-"`
}

// TypeName is the record's type mnemonic.
func (r RR) TypeName() string { return TypeString(r.Type) }

// EDNS is the OPT pseudo-record's content (RFC 6891).
type EDNS struct {
	UDPSize uint16 `json:"udp_size"`
	Version uint8  `json:"version"`
	DO      bool   `json:"do"`
}

// Msg is a parsed DNS message.
type Msg struct {
	ID         uint16     `json:"id"`
	Response   bool       `json:"-"`
	Opcode     int        `json:"opcode"`
	AA         bool       `json:"aa"` // authoritative answer
	TC         bool       `json:"tc"` // truncated
	RD         bool       `json:"rd"` // recursion desired
	RA         bool       `json:"ra"` // recursion available
	AD         bool       `json:"ad"` // authenticated data (DNSSEC-validated)
	CD         bool       `json:"cd"` // checking disabled
	Rcode      int        `json:"-"`  // including EDNS extended bits
	Question   []Question `json:"question"`
	Answer     []RR       `json:"answer"`
	Authority  []RR       `json:"authority"`
	Additional []RR       `json:"additional"`
	EDNS       *EDNS      `json:"edns,omitempty"`
}

// Flags lists the set header flags as dig prints them: "qr aa rd ra ad".
func (m *Msg) Flags() string {
	var f []string
	for _, x := range []struct {
		on   bool
		name string
	}{{m.Response, "qr"}, {m.AA, "aa"}, {m.TC, "tc"}, {m.RD, "rd"}, {m.RA, "ra"}, {m.AD, "ad"}, {m.CD, "cd"}} {
		if x.on {
			f = append(f, x.name)
		}
	}
	return strings.Join(f, " ")
}

// Query is what to ask.
type Query struct {
	ID        uint16
	Name      string
	Type      uint16
	Recursion bool   // RD: ask the server to resolve it fully
	DNSSEC    bool   // EDNS DO: ask for signatures
	CD        bool   // checking disabled: don't validate, return what there is
	UDPSize   uint16 // EDNS buffer size; 0 = 1232
	NoEDNS    bool   // leave out the OPT record entirely
}

// Fqdn makes a name absolute ("example.com" → "example.com.").
func Fqdn(name string) string {
	if strings.HasSuffix(name, ".") {
		return name
	}
	return name + "."
}

func appendName(b []byte, name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0), nil
	}
	if len(name) > 253 {
		return nil, fmt.Errorf("%q is longer than 253 characters", name)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return nil, fmt.Errorf("%q has an empty or too long label", name)
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0), nil
}

// Pack builds the query message.
func (q Query) Pack() ([]byte, error) {
	var flags uint16
	if q.Recursion {
		flags |= 0x0100
	}
	if q.CD {
		flags |= 0x0010
	}
	b := make([]byte, 12, 128)
	binary.BigEndian.PutUint16(b[0:], q.ID)
	binary.BigEndian.PutUint16(b[2:], flags)
	binary.BigEndian.PutUint16(b[4:], 1)
	if !q.NoEDNS {
		binary.BigEndian.PutUint16(b[10:], 1)
	}
	b, err := appendName(b, q.Name)
	if err != nil {
		return nil, err
	}
	b = binary.BigEndian.AppendUint16(b, q.Type)
	b = binary.BigEndian.AppendUint16(b, ClassIN)
	if !q.NoEDNS {
		size := q.UDPSize
		if size == 0 {
			size = 1232 // the DNS flag day 2020 default, avoids fragmentation
		}
		ttl := uint32(0)
		if q.DNSSEC {
			ttl |= 0x8000
		}
		b = append(b, 0)
		b = binary.BigEndian.AppendUint16(b, TypeOPT)
		b = binary.BigEndian.AppendUint16(b, size)
		b = binary.BigEndian.AppendUint32(b, ttl)
		b = binary.BigEndian.AppendUint16(b, 0)
	}
	return b, nil
}

var errShort = errors.New("dns: message ends early")

// readName reads a possibly compressed name at off; it returns the name
// and the offset just after it in the original position.
func readName(msg []byte, off int) (string, int, error) {
	var labels []string
	next, jumped := -1, false
	for hops := 0; hops < 128; hops++ {
		if off >= len(msg) {
			return "", 0, errShort
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
				return "", 0, errShort
			}
			if !jumped {
				next = off + 2
			}
			ptr := (l&0x3F)<<8 | int(msg[off+1])
			if ptr >= off { // pointers must point backwards; this stops loops
				return "", 0, errors.New("dns: bad name pointer")
			}
			off, jumped = ptr, true
		case l&0xC0 != 0:
			return "", 0, errors.New("dns: unknown label type")
		default:
			if off+1+l > len(msg) {
				return "", 0, errShort
			}
			labels = append(labels, escapeLabel(msg[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, errors.New("dns: name too long")
}

// escapeLabel writes a label the way zone files do: dots and backslashes
// escaped, unprintable bytes as \DDD.
func escapeLabel(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		switch {
		case c == '.' || c == '\\':
			s.WriteByte('\\')
			s.WriteByte(c)
		case c < 0x21 || c > 0x7e:
			fmt.Fprintf(&s, "\\%03d", c)
		default:
			s.WriteByte(c)
		}
	}
	return s.String()
}

// Parse decodes a whole message, keeping its sections apart.
func Parse(b []byte) (*Msg, error) {
	if len(b) < 12 {
		return nil, errShort
	}
	h := binary.BigEndian.Uint16(b[2:])
	m := &Msg{
		ID: binary.BigEndian.Uint16(b), Response: h&0x8000 != 0, Opcode: int(h>>11) & 0xF,
		AA: h&0x0400 != 0, TC: h&0x0200 != 0, RD: h&0x0100 != 0, RA: h&0x0080 != 0,
		AD: h&0x0020 != 0, CD: h&0x0010 != 0, Rcode: int(h & 0xF),
	}
	counts := []int{int(binary.BigEndian.Uint16(b[4:])), int(binary.BigEndian.Uint16(b[6:])), int(binary.BigEndian.Uint16(b[8:])), int(binary.BigEndian.Uint16(b[10:]))}
	off := 12
	for i := 0; i < counts[0]; i++ {
		name, n, err := readName(b, off)
		if err != nil || n+4 > len(b) {
			return nil, errors.New("dns: bad question")
		}
		m.Question = append(m.Question, Question{name, binary.BigEndian.Uint16(b[n:]), binary.BigEndian.Uint16(b[n+2:])})
		off = n + 4
	}
	sections := []*[]RR{&m.Answer, &m.Authority, &m.Additional}
	for s, sec := range sections {
		for i := 0; i < counts[s+1]; i++ {
			name, n, err := readName(b, off)
			if err != nil || n+10 > len(b) {
				return m, fmt.Errorf("dns: record %d in section %d: %w", i+1, s+2, errShort)
			}
			rr := RR{Name: name, Type: binary.BigEndian.Uint16(b[n:]), Class: binary.BigEndian.Uint16(b[n+2:]), TTL: binary.BigEndian.Uint32(b[n+4:])}
			rdlen := int(binary.BigEndian.Uint16(b[n+8:]))
			start := n + 10
			if start+rdlen > len(b) {
				return m, errShort
			}
			rr.Raw = append([]byte(nil), b[start:start+rdlen]...)
			off = start + rdlen
			if rr.Type == TypeOPT {
				// The OPT record's class is the UDP size; its TTL holds the
				// extended rcode, the version and the DO bit.
				m.EDNS = &EDNS{UDPSize: rr.Class, Version: uint8(rr.TTL >> 16), DO: rr.TTL&0x8000 != 0}
				m.Rcode |= int(rr.TTL>>24) << 4
				continue
			}
			rr.Data = rdata(b, start, rdlen, rr.Type)
			*sec = append(*sec, rr)
		}
	}
	return m, nil
}

// ReverseName is the PTR name for an address: in-addr.arpa for IPv4,
// nibbles under ip6.arpa for IPv6.
func ReverseName(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d.in-addr.arpa.", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := ip.To16()
	if v6 == nil {
		return ""
	}
	const hex = "0123456789abcdef"
	var b strings.Builder
	for i := 15; i >= 0; i-- {
		b.WriteByte(hex[v6[i]&0xF])
		b.WriteByte('.')
		b.WriteByte(hex[v6[i]>>4])
		b.WriteByte('.')
	}
	return b.String() + "ip6.arpa."
}
