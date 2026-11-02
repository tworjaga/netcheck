// Package dnsx is a complete DNS message codec and the transports to send
// queries over UDP, TCP, DNS over TLS and DNS over HTTPS. It backs the
// Advanced-mode DNS tools; the small codec in probe stays for the checks
// that only need a few record types.
package dnsx

import (
	"strconv"
	"strings"
)

// Record types, by their registered numbers.
const (
	TypeA      uint16 = 1
	TypeNS     uint16 = 2
	TypeCNAME  uint16 = 5
	TypeSOA    uint16 = 6
	TypePTR    uint16 = 12
	TypeMX     uint16 = 15
	TypeTXT    uint16 = 16
	TypeAAAA   uint16 = 28
	TypeSRV    uint16 = 33
	TypeNAPTR  uint16 = 35
	TypeDNAME  uint16 = 39
	TypeOPT    uint16 = 41
	TypeDS     uint16 = 43
	TypeSSHFP  uint16 = 44
	TypeRRSIG  uint16 = 46
	TypeNSEC   uint16 = 47
	TypeDNSKEY uint16 = 48
	TypeNSEC3  uint16 = 50
	TypeTLSA   uint16 = 52
	TypeSVCB   uint16 = 64
	TypeHTTPS  uint16 = 65
	TypeANY    uint16 = 255
	TypeCAA    uint16 = 257

	ClassIN uint16 = 1
)

var typeNames = map[uint16]string{
	TypeA: "A", TypeNS: "NS", TypeCNAME: "CNAME", TypeSOA: "SOA", TypePTR: "PTR",
	TypeMX: "MX", TypeTXT: "TXT", TypeAAAA: "AAAA", TypeSRV: "SRV", TypeNAPTR: "NAPTR",
	TypeDNAME: "DNAME", TypeOPT: "OPT", TypeDS: "DS", TypeSSHFP: "SSHFP", TypeRRSIG: "RRSIG",
	TypeNSEC: "NSEC", TypeDNSKEY: "DNSKEY", TypeNSEC3: "NSEC3", TypeTLSA: "TLSA",
	TypeSVCB: "SVCB", TypeHTTPS: "HTTPS", TypeANY: "ANY", TypeCAA: "CAA",
}

// TypeString is a type's mnemonic, or "TYPE123" for one without a name.
func TypeString(t uint16) string {
	if s, ok := typeNames[t]; ok {
		return s
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType reads "MX", "mx" or "TYPE15".
func ParseType(s string) (uint16, bool) {
	s = strings.ToUpper(strings.TrimSpace(s))
	for t, n := range typeNames {
		if n == s {
			return t, true
		}
	}
	if strings.HasPrefix(s, "TYPE") {
		if n, err := strconv.Atoi(s[4:]); err == nil && n >= 0 && n <= 65535 {
			return uint16(n), true
		}
	}
	return 0, false
}

// Response codes.
const (
	RcodeSuccess  = 0
	RcodeFormErr  = 1
	RcodeServFail = 2
	RcodeNXDomain = 3
	RcodeNotImp   = 4
	RcodeRefused  = 5
	RcodeBadVers  = 16
)

var rcodeNames = map[int]string{
	RcodeSuccess: "NOERROR", RcodeFormErr: "FORMERR", RcodeServFail: "SERVFAIL",
	RcodeNXDomain: "NXDOMAIN", RcodeNotImp: "NOTIMP", RcodeRefused: "REFUSED", RcodeBadVers: "BADVERS",
}

// RcodeString names a response code.
func RcodeString(r int) string {
	if s, ok := rcodeNames[r]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(r)
}

// DNSSEC algorithm names, for presentation.
var algNames = map[uint8]string{
	5: "RSASHA1", 7: "RSASHA1-NSEC3", 8: "RSASHA256", 10: "RSASHA512",
	13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384", 15: "ED25519", 16: "ED448",
}

// AlgString names a DNSSEC algorithm.
func AlgString(a uint8) string {
	if s, ok := algNames[a]; ok {
		return s
	}
	return strconv.Itoa(int(a))
}
