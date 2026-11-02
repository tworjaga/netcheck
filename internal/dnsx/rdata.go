package dnsx

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// rdata formats record data the way zone files and dig print it. Unknown or
// malformed data uses the generic form from RFC 3597: \# length hex.
func rdata(msg []byte, start, n int, t uint16) string {
	rd := msg[start : start+n]
	if s, ok := formatKnown(msg, start, rd, t); ok {
		return s
	}
	return fmt.Sprintf("\\# %d %s", n, strings.ToUpper(hex.EncodeToString(rd)))
}

func name(msg []byte, off int) (string, bool) {
	s, _, err := readName(msg, off)
	return s, err == nil
}

func u16(b []byte, i int) uint16 { return binary.BigEndian.Uint16(b[i:]) }
func u32(b []byte, i int) uint32 { return binary.BigEndian.Uint32(b[i:]) }

// characterStrings reads the <character-string> list of TXT and friends.
func characterStrings(b []byte) ([]string, bool) {
	var out []string
	for i := 0; i < len(b); {
		l := int(b[i])
		if i+1+l > len(b) {
			return nil, false
		}
		out = append(out, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	return out, true
}

func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range []byte(s) {
		switch {
		case c == '"' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c < 0x20 || c > 0x7e:
			fmt.Fprintf(&b, "\\%03d", c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// sigTime prints an RRSIG timestamp as YYYYMMDDHHMMSS.
func sigTime(v uint32) string {
	return time.Unix(int64(v), 0).UTC().Format("20060102150405")
}

// typeBitmap reads the NSEC/NSEC3 window bitmap into type names.
func typeBitmap(b []byte) []string {
	var out []string
	for i := 0; i+2 <= len(b); {
		win, l := int(b[i]), int(b[i+1])
		if i+2+l > len(b) {
			break
		}
		for j, octet := range b[i+2 : i+2+l] {
			for bit := 0; bit < 8; bit++ {
				if octet&(0x80>>bit) != 0 {
					out = append(out, TypeString(uint16(win*256+j*8+bit)))
				}
			}
		}
		i += 2 + l
	}
	return out
}

func formatKnown(msg []byte, start int, rd []byte, t uint16) (string, bool) {
	switch t {
	case TypeA:
		if len(rd) == 4 {
			return net.IP(rd).String(), true
		}
	case TypeAAAA:
		if len(rd) == 16 {
			return net.IP(rd).String(), true
		}
	case TypeNS, TypeCNAME, TypePTR, TypeDNAME:
		return name(msg, start)
	case TypeMX:
		if len(rd) > 2 {
			if n, ok := name(msg, start+2); ok {
				return fmt.Sprintf("%d %s", u16(rd, 0), n), true
			}
		}
	case TypeTXT:
		if ss, ok := characterStrings(rd); ok {
			for i := range ss {
				ss[i] = quote(ss[i])
			}
			return strings.Join(ss, " "), true
		}
	case TypeSOA:
		mname, n1, err := readName(msg, start)
		if err != nil {
			return "", false
		}
		rname, n2, err := readName(msg, n1)
		if err != nil || n2+20 > start+len(rd) {
			return "", false
		}
		v := msg[n2:]
		return fmt.Sprintf("%s %s %d %d %d %d %d", mname, rname, u32(v, 0), u32(v, 4), u32(v, 8), u32(v, 12), u32(v, 16)), true
	case TypeSRV:
		if len(rd) > 6 {
			if n, ok := name(msg, start+6); ok {
				return fmt.Sprintf("%d %d %d %s", u16(rd, 0), u16(rd, 2), u16(rd, 4), n), true
			}
		}
	case TypeCAA:
		if len(rd) >= 2 && 2+int(rd[1]) <= len(rd) {
			tag := string(rd[2 : 2+int(rd[1])])
			return fmt.Sprintf("%d %s %s", rd[0], tag, quote(string(rd[2+int(rd[1]):]))), true
		}
	case TypeDS:
		if len(rd) > 4 {
			return fmt.Sprintf("%d %d %d %s", u16(rd, 0), rd[2], rd[3], strings.ToUpper(hex.EncodeToString(rd[4:]))), true
		}
	case TypeDNSKEY:
		if len(rd) > 4 {
			return fmt.Sprintf("%d %d %d %s", u16(rd, 0), rd[2], rd[3], base64.StdEncoding.EncodeToString(rd[4:])), true
		}
	case TypeRRSIG:
		if len(rd) > 18 {
			if signer, n, err := readName(msg, start+18); err == nil && n <= start+len(rd) {
				sig := base64.StdEncoding.EncodeToString(msg[n : start+len(rd)])
				return fmt.Sprintf("%s %d %d %d %s %s %d %s %s", TypeString(u16(rd, 0)), rd[2], rd[3], u32(rd, 4),
					sigTime(u32(rd, 8)), sigTime(u32(rd, 12)), u16(rd, 16), signer, sig), true
			}
		}
	case TypeNSEC:
		if next, n, err := readName(msg, start); err == nil && n <= start+len(rd) {
			return strings.TrimSpace(next + " " + strings.Join(typeBitmap(msg[n:start+len(rd)]), " ")), true
		}
	case TypeSSHFP:
		if len(rd) > 2 {
			return fmt.Sprintf("%d %d %s", rd[0], rd[1], strings.ToUpper(hex.EncodeToString(rd[2:]))), true
		}
	case TypeTLSA:
		if len(rd) > 3 {
			return fmt.Sprintf("%d %d %d %s", rd[0], rd[1], rd[2], strings.ToUpper(hex.EncodeToString(rd[3:]))), true
		}
	}
	return "", false
}

// Summary is a short human form of the record for tables: DNSKEY and
// RRSIG keys and signatures are cut down to what a person reads.
func (r RR) Summary() string {
	f := strings.Fields(r.Data)
	switch r.Type {
	case TypeDNSKEY:
		if len(f) >= 4 {
			kind := "ZSK"
			if f[0] == "257" {
				kind = "KSK"
			}
			alg, _ := strconv.Atoi(f[2])
			return fmt.Sprintf("%s %s %s", f[0], kind, AlgString(uint8(alg)))
		}
	case TypeRRSIG:
		if len(f) >= 8 {
			alg, _ := strconv.Atoi(f[1])
			exp, _ := time.Parse("20060102150405", f[4])
			return fmt.Sprintf("%s %s expires %s · %s", f[0], AlgString(uint8(alg)), exp.Format("2006-01-02"), f[7])
		}
	}
	return r.Data
}
