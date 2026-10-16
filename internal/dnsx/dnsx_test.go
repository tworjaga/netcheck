package dnsx

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// wire builds DNS messages for tests.
type wire struct{ b []byte }

func (w *wire) name(n string) {
	w.b, _ = appendName(w.b, n)
}

func (w *wire) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *wire) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }

// rr appends a record whose data is built by data (it can use names).
func (w *wire) rr(name string, t uint16, ttl uint32, data func(w *wire)) {
	w.name(name)
	w.u16(t)
	w.u16(ClassIN)
	w.u32(ttl)
	lenAt := len(w.b)
	w.u16(0)
	data(w)
	binary.BigEndian.PutUint16(w.b[lenAt:], uint16(len(w.b)-lenAt-2))
}

// answer is a response to query with the given answer records (counts in
// the header are set from n).
func answer(query []byte, flags uint16, n [3]int, body func(w *wire)) []byte {
	q, _ := Parse(query)
	w := &wire{b: make([]byte, 12)}
	binary.BigEndian.PutUint16(w.b[0:], q.ID)
	binary.BigEndian.PutUint16(w.b[2:], 0x8000|flags)
	binary.BigEndian.PutUint16(w.b[4:], 1)
	binary.BigEndian.PutUint16(w.b[6:], uint16(n[0]))
	binary.BigEndian.PutUint16(w.b[8:], uint16(n[1]))
	binary.BigEndian.PutUint16(w.b[10:], uint16(n[2]))
	w.name(q.Question[0].Name)
	w.u16(q.Question[0].Type)
	w.u16(ClassIN)
	body(w)
	return w.b
}

func TestPackParseQuery(t *testing.T) {
	b, err := Query{ID: 0xBEEF, Name: "example.com", Type: TypeMX, Recursion: true, DNSSEC: true}.Pack()
	if err != nil {
		t.Fatal(err)
	}
	m, err := Parse(b)
	if err != nil || m.ID != 0xBEEF || !m.RD || len(m.Question) != 1 || m.Question[0].Name != "example.com." || m.Question[0].Type != TypeMX {
		t.Fatalf("got %+v %v", m, err)
	}
	if m.EDNS == nil || !m.EDNS.DO || m.EDNS.UDPSize != 1232 {
		t.Errorf("EDNS: %+v", m.EDNS)
	}
	if _, err := (Query{Name: strings.Repeat("a", 64) + ".com"}).Pack(); err == nil {
		t.Error("a label over 63 bytes is refused")
	}
}

func TestRecordFormats(t *testing.T) {
	q, _ := Query{ID: 7, Name: "example.com", Type: TypeANY}.Pack()
	key, _ := base64.StdEncoding.DecodeString("AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF")
	msg := answer(q, 0x0400|0x0080|0x0020, [3]int{12, 0, 0}, func(w *wire) {
		w.rr("example.com", TypeA, 300, func(w *wire) { w.b = append(w.b, 93, 184, 216, 34) })
		w.rr("example.com", TypeAAAA, 300, func(w *wire) { w.b = append(w.b, net.ParseIP("2606:2800:220:1::1")...) })
		w.rr("example.com", TypeMX, 3600, func(w *wire) { w.u16(10); w.name("mail.example.com") })
		w.rr("example.com", TypeTXT, 60, func(w *wire) {
			for _, s := range []string{"v=spf1 -all", `say "hi"`} {
				w.b = append(w.b, byte(len(s)))
				w.b = append(w.b, s...)
			}
		})
		w.rr("example.com", TypeSOA, 3600, func(w *wire) {
			w.name("ns.icann.org")
			w.name("noc.dns.icann.org")
			for _, v := range []uint32{2024101401, 7200, 3600, 1209600, 3600} {
				w.u32(v)
			}
		})
		w.rr("_sip._tcp.example.com", TypeSRV, 60, func(w *wire) { w.u16(10); w.u16(60); w.u16(5060); w.name("sip.example.com") })
		w.rr("example.com", TypeCAA, 60, func(w *wire) { w.b = append(w.b, 0, 5); w.b = append(w.b, "issueletsencrypt.org"...) })
		w.rr("example.com", TypeDS, 60, func(w *wire) { w.u16(370); w.b = append(w.b, 13, 2, 0xAB, 0xCD) })
		w.rr("example.com", TypeDNSKEY, 60, func(w *wire) { w.u16(257); w.b = append(w.b, 3, 13); w.b = append(w.b, key...) })
		w.rr("example.com", TypeRRSIG, 60, func(w *wire) {
			w.u16(TypeA)
			w.b = append(w.b, 13, 2)
			w.u32(300)
			w.u32(uint32(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC).Unix()))
			w.u32(uint32(time.Date(2026, 10, 11, 0, 0, 0, 0, time.UTC).Unix()))
			w.u16(12345)
			w.name("example.com")
			w.b = append(w.b, 1, 2, 3)
		})
		w.rr("example.com", TypeNSEC, 60, func(w *wire) {
			w.name("www.example.com")
			w.b = append(w.b, 0, 1, 0x62) // window 0: A(1) NS(2) SOA(6)
		})
		w.rr("example.com", 999, 60, func(w *wire) { w.b = append(w.b, 0xDE, 0xAD) })
	})
	m, err := Parse(msg)
	if err != nil {
		t.Fatal(err)
	}
	if !m.AA || !m.RA || !m.AD || m.Flags() != "qr aa ra ad" {
		t.Errorf("flags: %q", m.Flags())
	}
	want := []string{
		"93.184.216.34",
		"2606:2800:220:1::1",
		"10 mail.example.com.",
		`"v=spf1 -all" "say \"hi\""`,
		"ns.icann.org. noc.dns.icann.org. 2024101401 7200 3600 1209600 3600",
		"10 60 5060 sip.example.com.",
		`0 issue "letsencrypt.org"`,
		"370 13 2 ABCD",
		"257 3 13 " + base64.StdEncoding.EncodeToString(key),
		"A 13 2 300 20261101000000 20261011000000 12345 example.com. AQID",
		"www.example.com. A NS SOA",
		`\# 2 DEAD`,
	}
	if len(m.Answer) != len(want) {
		t.Fatalf("%d answers", len(m.Answer))
	}
	for i, w := range want {
		if m.Answer[i].Data != w {
			t.Errorf("%s: got %q, want %q", m.Answer[i].TypeName(), m.Answer[i].Data, w)
		}
	}
	if s := m.Answer[8].Summary(); s != "257 KSK ECDSAP256SHA256" {
		t.Errorf("DNSKEY summary: %q", s)
	}
	if s := m.Answer[9].Summary(); s != "A ECDSAP256SHA256 expires 2026-11-01 · example.com." {
		t.Errorf("RRSIG summary: %q", s)
	}
	if m.Answer[11].TypeName() != "TYPE999" {
		t.Errorf("unknown type name: %s", m.Answer[11].TypeName())
	}
}

func TestCompressionAndLoops(t *testing.T) {
	q, _ := Query{ID: 1, Name: "example.com", Type: TypeCNAME}.Pack()
	// "www.example.com" CNAME pointing back at the question's name (offset 12).
	msg := answer(q, 0, [3]int{1, 0, 0}, func(w *wire) {
		w.b = append(w.b, 3, 'w', 'w', 'w', 0xC0, 12)
		w.u16(TypeCNAME)
		w.u16(ClassIN)
		w.u32(60)
		w.u16(2)
		w.b = append(w.b, 0xC0, 12)
	})
	m, err := Parse(msg)
	if err != nil || m.Answer[0].Name != "www.example.com." || m.Answer[0].Data != "example.com." {
		t.Fatalf("compression: %+v %v", m, err)
	}
	loop := append([]byte(nil), msg...)
	loop[12] = 0xC0 // the question's name now points at itself
	loop[13] = 12
	if _, err := Parse(loop); err == nil {
		t.Error("a pointer loop must be rejected")
	}
}

func TestEDNSExtendedRcode(t *testing.T) {
	q, _ := Query{ID: 9, Name: "example.com", Type: TypeA}.Pack()
	msg := answer(q, 0, [3]int{0, 0, 1}, func(w *wire) {
		w.b = append(w.b, 0)
		w.u16(TypeOPT)
		w.u16(4096)
		w.u32(1<<24 | 0x8000) // extended rcode 1 (BADVERS with low bits 0), DO
		w.u16(0)
	})
	m, _ := Parse(msg)
	if m.Rcode != RcodeBadVers || m.EDNS == nil || !m.EDNS.DO || m.EDNS.UDPSize != 4096 || len(m.Additional) != 0 {
		t.Errorf("rcode %d (%s), edns %+v", m.Rcode, RcodeString(m.Rcode), m.EDNS)
	}
}

func TestReverseName(t *testing.T) {
	if r := ReverseName(net.ParseIP("192.0.2.5")); r != "5.2.0.192.in-addr.arpa." {
		t.Errorf("v4: %s", r)
	}
	if r := ReverseName(net.ParseIP("2001:db8::1")); r != "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa." {
		t.Errorf("v6: %s", r)
	}
}

func TestParseServer(t *testing.T) {
	cases := []struct{ in, tr, addr, url, transport string }{
		{"1.1.1.1", "", "1.1.1.1:53", "", UDP},
		{"@ns1.example.com:5353", TCP, "ns1.example.com:5353", "", TCP},
		{"[2606:4700:4700::1111]", DoT, "[2606:4700:4700::1111]:853", "", DoT},
		{"cloudflare", DoT, "1.1.1.1:853", "", DoT},
		{"google", DoH, "", "https://dns.google/dns-query", DoH},
		{"9.9.9.9", DoH, "", "https://9.9.9.9/dns-query", DoH},
		{"https://doh.example/q", "", "", "https://doh.example/q", DoH},
	}
	for _, c := range cases {
		s, err := ParseServer(c.in, c.tr)
		if err != nil || s.Addr != c.addr || s.URL != c.url || s.Transport != c.transport {
			t.Errorf("%q/%q: got %+v %v", c.in, c.tr, s, err)
		}
	}
	if _, err := ParseServer("1.1.1.1:99999", ""); err == nil {
		t.Error("bad port")
	}
}

// fakeDNS answers every query with one A record 192.0.2.1, or with a
// truncated empty answer over UDP when big is set.
func fakeAnswer(q []byte, udp, big bool) []byte {
	if udp && big {
		return answer(q, 0x0200, [3]int{0, 0, 0}, func(*wire) {})
	}
	return answer(q, 0x0080, [3]int{1, 0, 0}, func(w *wire) {
		w.rr("example.com", TypeA, 60, func(w *wire) { w.b = append(w.b, 192, 0, 2, 1) })
	})
}

func serveUDP(t *testing.T, big bool) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
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
			pc.WriteTo(fakeAnswer(buf[:n], true, big), from)
		}
	}()
	return pc.LocalAddr().String()
}

func serveStream(t *testing.T, l net.Listener) string {
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var n [2]byte
				if _, err := io.ReadFull(c, n[:]); err != nil {
					return
				}
				q := make([]byte, binary.BigEndian.Uint16(n[:]))
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				a := fakeAnswer(q, false, false)
				c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
			}(c)
		}
	}()
	return l.Addr().String()
}

func checkA(t *testing.T, name string, r *Result, err error, transport string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].Data != "192.0.2.1" || r.Transport != transport || r.Size == 0 {
		t.Fatalf("%s: got %+v / %+v", name, r, r.Msg)
	}
}

func TestExchangeTransports(t *testing.T) {
	ctx := context.Background()
	q := Query{Name: "example.com", Type: TypeA, Recursion: true}

	r, err := Exchange(ctx, Server{Addr: serveUDP(t, false), Transport: UDP}, q, 2*time.Second)
	checkA(t, "udp", r, err, UDP)

	l, _ := net.Listen("tcp", "127.0.0.1:0")
	tcpAddr := serveStream(t, l)
	r, err = Exchange(ctx, Server{Addr: tcpAddr, Transport: TCP}, q, 2*time.Second)
	checkA(t, "tcp", r, err, TCP)

	// A truncated UDP answer is retried over TCP on the same address.
	pc, _ := net.ListenPacket("udp", tcpAddr)
	if pc != nil {
		t.Cleanup(func() { pc.Close() })
		go func() {
			buf := make([]byte, 1500)
			n, from, err := pc.ReadFrom(buf)
			if err == nil {
				pc.WriteTo(fakeAnswer(buf[:n], true, true), from)
			}
		}()
		r, err = Exchange(ctx, Server{Addr: tcpAddr, Transport: UDP}, q, 2*time.Second)
		checkA(t, "udp→tcp", r, err, TCP)
		if !r.Retried {
			t.Error("Retried should be set")
		}
	}

	// DNS over TLS, against a local certificate.
	ts := httptest.NewTLSServer(http.NotFoundHandler())
	pool := ts.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	cert := ts.TLS.Certificates
	ts.Close()
	tl, _ := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert})
	dotAddr := serveStream(t, tl)
	srv := Server{Addr: dotAddr, Transport: DoT, tlsConfig: &tls.Config{RootCAs: pool, ServerName: "example.com"}}
	r, err = Exchange(ctx, srv, q, 2*time.Second)
	checkA(t, "dot", r, err, DoT)
	srv.tlsConfig = &tls.Config{ServerName: "example.com"} // not trusting the test CA
	if _, err := Exchange(ctx, srv, q, 2*time.Second); err == nil {
		t.Error("DoT must verify the server's certificate")
	}

	// DNS over HTTPS.
	doh := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" {
			http.Error(w, "bad", 400)
			return
		}
		q, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(fakeAnswer(q, false, false))
	}))
	defer doh.Close()
	r, err = Exchange(ctx, Server{URL: doh.URL + "/dns-query", Transport: DoH, httpClient: doh.Client()}, q, 2*time.Second)
	checkA(t, "doh", r, err, DoH)
}

func TestExchangeTimeout(t *testing.T) {
	pc, _ := net.ListenPacket("udp", "127.0.0.1:0") // listens, never answers
	defer pc.Close()
	_, err := Exchange(context.Background(), Server{Addr: pc.LocalAddr().String(), Transport: UDP}, Query{Name: "example.com", Type: TypeA}, 200*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Errorf("got %v", err)
	}
}
