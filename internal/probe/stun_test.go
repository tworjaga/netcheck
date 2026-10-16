package probe

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
)

// rfc5769Response is the "sample IPv4 response" from RFC 5769, section 2.2:
// XOR-MAPPED-ADDRESS 192.0.2.1:32853, with SOFTWARE, MESSAGE-INTEGRITY and
// FINGERPRINT around it.
var rfc5769Response = []byte{
	0x01, 0x01, 0x00, 0x3c, 0x21, 0x12, 0xa4, 0x42,
	0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
	0x80, 0x22, 0x00, 0x0b, 0x74, 0x65, 0x73, 0x74, 0x20, 0x76, 0x65, 0x63, 0x74, 0x6f, 0x72, 0x20,
	0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43,
	0x00, 0x08, 0x00, 0x14, 0x2b, 0x91, 0xf5, 0x99, 0xfd, 0x9e, 0x90, 0xc3, 0x8c, 0x74, 0x89, 0xf9, 0x2a, 0xf9, 0xba, 0x53, 0xf0, 0x6b, 0xe7, 0xd7,
	0x80, 0x28, 0x00, 0x04, 0xc0, 0x7d, 0x4c, 0x96,
}

var rfc5769TxID = [12]byte{0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae}

func TestParseSTUNRFC5769(t *testing.T) {
	a, ok := parseSTUN(rfc5769Response, rfc5769TxID)
	if !ok || a.String() != "192.0.2.1:32853" {
		t.Fatalf("got %v %v", a, ok)
	}
	other := rfc5769TxID
	other[0] ^= 1
	if _, ok := parseSTUN(rfc5769Response, other); ok {
		t.Error("someone else's transaction must not match")
	}
	if _, ok := parseSTUN(rfc5769Response[:30], rfc5769TxID); ok {
		t.Error("a truncated answer must not parse")
	}
	req := stunRequest(rfc5769TxID)
	if len(req) != 20 || binary.BigEndian.Uint16(req) != 0x0001 || binary.BigEndian.Uint32(req[4:]) != stunMagic || [12]byte(req[8:20]) != rfc5769TxID {
		t.Errorf("request: % x", req)
	}
}

// stunResponse answers a request with XOR-MAPPED-ADDRESS addr.
func stunResponse(req []byte, addr *net.UDPAddr) []byte {
	b := make([]byte, 32)
	binary.BigEndian.PutUint16(b, stunBindingSuccess)
	binary.BigEndian.PutUint16(b[2:], 12)
	copy(b[4:20], req[4:20]) // magic and transaction ID
	binary.BigEndian.PutUint16(b[20:], stunXorMappedAddress)
	binary.BigEndian.PutUint16(b[22:], 8)
	b[25] = 1
	binary.BigEndian.PutUint16(b[26:], uint16(addr.Port)^uint16(stunMagic>>16))
	ip := addr.IP.To4()
	for k := 0; k < 4; k++ {
		b[28+k] = ip[k] ^ stunCookie[k]
	}
	return b
}

// fakeSTUN is a STUN server on localhost that reports mapped as the
// sender's address, or stays silent when mapped is nil.
func fakeSTUN(t *testing.T, mapped *net.UDPAddr) string {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if mapped != nil && n >= 20 {
				_, _ = pc.WriteTo(stunResponse(buf[:n], mapped), from)
			}
		}
	}()
	return pc.LocalAddr().String()
}

func udp(s string) *net.UDPAddr { a, _ := net.ResolveUDPAddr("udp4", s); return a }

func TestDetectNATMapping(t *testing.T) {
	swap(t, &localAddrs, func() []net.IP { return []net.IP{net.ParseIP("192.168.0.200")} })
	cases := []struct {
		name      string
		a, b      *net.UDPAddr
		behaviour string
		public    string
		answered  int
	}{
		{"one port for all", udp("203.0.113.7:40001"), udp("203.0.113.7:40001"), "endpoint-independent", "203.0.113.7", 2},
		{"new port each", udp("203.0.113.7:40001"), udp("203.0.113.7:40017"), "address-dependent", "203.0.113.7", 2},
		{"one silent", udp("203.0.113.7:40001"), nil, "unknown", "203.0.113.7", 1},
		{"udp blocked", nil, nil, "udp-blocked", "", 0},
		{"no nat", udp("192.168.0.200:5000"), udp("192.168.0.200:5000"), "none", "192.168.0.200", 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			swap(t, &stunServers, []string{fakeSTUN(t, c.a), fakeSTUN(t, c.b)})
			m := DetectNATMapping(context.Background())
			answered := 0
			for _, a := range m.Answers {
				if a.Mapped != "" {
					answered++
				}
			}
			if m.Behaviour != c.behaviour || m.Public != c.public || answered != c.answered || len(m.Answers) != 2 {
				t.Fatalf("got %+v", m)
			}
		})
	}
}
