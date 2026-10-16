package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"regexp"
	"runtime"
	"time"
)

var reIPv4 = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b`)

// parseNetshDNS pulls the DNS server addresses out of
// `netsh interface ipv4 show dnsservers`. The labels are localized but the
// addresses aren't, so only the addresses are read, in order.
func parseNetshDNS(out string) []string {
	seen := map[string]bool{}
	var res []string
	for _, m := range reIPv4.FindAllString(out, -1) {
		ip := net.ParseIP(m)
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || seen[m] {
			continue
		}
		seen[m] = true
		res = append(res, m)
	}
	return res
}

// DNSServers returns the DNS servers this machine is configured to use.
// Unlike SystemNameservers it also works on Windows (via netsh).
func DNSServers(ctx context.Context) []string {
	if runtime.GOOS != "windows" {
		return SystemNameservers()
	}
	out, _ := Run(ctx, 5*time.Second, "netsh", "interface", "ipv4", "show", "dnsservers")
	return parseNetshDNS(out)
}

// dnsExchange is a test seam: send query q to server (host:port) and return
// the raw answer. It retries over TCP when the UDP answer is truncated.
var dnsExchange = func(ctx context.Context, server string, q []byte, timeout time.Duration) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < 12 || binary.BigEndian.Uint16(buf) != binary.BigEndian.Uint16(q) {
			continue // stray or spoofed answer
		}
		if buf[2]&0x02 == 0 { // not truncated
			return append([]byte(nil), buf[:n]...), nil
		}
		break
	}
	tc, err := d.DialContext(ctx, "tcp", server)
	if err != nil {
		return nil, err
	}
	defer tc.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(dl)
	}
	msg := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := tc.Write(append(msg, q...)); err != nil {
		return nil, err
	}
	var l [2]byte
	if _, err := io.ReadFull(tc, l[:]); err != nil {
		return nil, err
	}
	resp := make([]byte, binary.BigEndian.Uint16(l[:]))
	_, err = io.ReadFull(tc, resp)
	return resp, err
}

// query sends one question with the DNSSEC OK bit and parses the answer.
func query(ctx context.Context, server, name string, qtype uint16) (*DNSMsg, error) {
	id := uint16(rand.UintN(1 << 16))
	b, err := dnsExchange(ctx, net.JoinHostPort(server, "53"), BuildQuery(id, name, qtype, true, true), 3*time.Second)
	if err != nil {
		return nil, err
	}
	m, err := ParseMsg(b)
	if err != nil {
		return nil, err
	}
	if m.ID != id || !m.Response {
		return nil, errors.New("dns: mismatched answer")
	}
	return m, nil
}

// DNS response codes.
const (
	rcodeOK       = 0
	rcodeServFail = 2
	rcodeNX       = 3
)

// Names for the DNSSEC test: one correctly signed, and test domains whose
// signatures are broken on purpose. A validating resolver answers the first
// with the AD bit set and refuses the others with SERVFAIL.
var (
	dnssecSigned = "cloudflare.com."
	dnssecBroken = []string{"dnssec-failed.org.", "fail01.dnssec.works."}
)

// DNSSECResult is one resolver's DNSSEC behaviour.
type DNSSECResult struct {
	Server   string `json:"server"`
	Answered bool   `json:"answered"`
	// AD: the signed name came back marked as validated.
	AD bool `json:"authenticated"`
	// Rejects: a deliberately broken name was refused (SERVFAIL).
	// RejectKnown is false when no broken test name gave a usable answer.
	Rejects     bool   `json:"rejects_bad_signatures"`
	RejectKnown bool   `json:"reject_tested"`
	Error       string `json:"error,omitempty"`
}

// CheckDNSSEC tests whether server validates DNSSEC.
func CheckDNSSEC(ctx context.Context, server string) DNSSECResult {
	r := DNSSECResult{Server: server}
	m, err := query(ctx, server, dnssecSigned, TypeA)
	if err != nil {
		r.Error = shortErr(err)
		return r
	}
	r.Answered = true
	r.AD = m.RCode == rcodeOK && m.AD
	for _, name := range dnssecBroken {
		b, err := query(ctx, server, name, TypeA)
		if err != nil {
			continue
		}
		switch b.RCode {
		case rcodeServFail:
			r.Rejects, r.RejectKnown = true, true
		case rcodeOK:
			if len(b.Answers) > 0 {
				r.Rejects, r.RejectKnown = false, true
			}
		}
		if r.RejectKnown {
			break
		}
	}
	return r
}
