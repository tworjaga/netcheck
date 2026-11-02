package domain

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// keyTag is a DNSKEY's tag (RFC 4034 appendix B), from its record data.
func keyTag(rdata []byte) uint16 {
	var ac uint32
	for i, b := range rdata {
		if i&1 == 1 {
			ac += uint32(b)
		} else {
			ac += uint32(b) << 8
		}
	}
	ac += ac >> 16 & 0xFFFF
	return uint16(ac & 0xFFFF)
}

// wireName is a name in canonical wire form: lower case, uncompressed.
func wireName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.Trim(strings.ToLower(name), "."), ".") {
		if l == "" {
			continue
		}
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

// dsDigest is the digest a DS record of the given type holds for a key.
func dsDigest(owner string, rdata []byte, digestType uint8) string {
	data := append(wireName(owner), rdata...)
	switch digestType {
	case 1:
		s := sha1.Sum(data)
		return hex.EncodeToString(s[:])
	case 2:
		s := sha256.Sum256(data)
		return hex.EncodeToString(s[:])
	case 4:
		s := sha512.Sum384(data)
		return hex.EncodeToString(s[:])
	}
	return ""
}

// algorithm grades: current, old (still works, should be replaced), and
// broken (deprecated, validators may ignore it).
func algStatus(a uint8) Status {
	switch a {
	case 8, 13, 14, 15, 16:
		return OK
	case 5, 7, 10:
		return Warn
	}
	return Bad
}

var digestNames = map[uint8]string{1: "SHA-1", 2: "SHA-256", 4: "SHA-384"}

func dnssec(ctx context.Context, zone string, parent []dnsx.NS) []Check {
	var cs []Check
	dsMsg, err := ask(ctx, zone, dnsx.TypeDS, true)
	if err != nil {
		return []Check{{AreaDNSSEC, Info, "Couldn't check", "the DS lookup failed: " + err.Error(), ""}}
	}
	ds := ofType(dsMsg.Answer, dnsx.TypeDS)

	// The keys and their signatures, straight from a nameserver.
	var keys, sigs []dnsx.RR
	for _, p := range parent {
		res, err := askNS(ctx, p.Addr, zone, dnsx.TypeDNSKEY, true)
		if err != nil || res.Msg.Rcode != dnsx.RcodeSuccess {
			continue
		}
		keys = ofType(res.Msg.Answer, dnsx.TypeDNSKEY)
		sigs = ofType(res.Msg.Answer, dnsx.TypeRRSIG)
		if soa, err := askNS(ctx, p.Addr, zone, dnsx.TypeSOA, true); err == nil {
			sigs = append(sigs, ofType(soa.Msg.Answer, dnsx.TypeRRSIG)...)
		}
		break
	}

	switch {
	case len(ds) == 0 && len(keys) == 0:
		return []Check{{AreaDNSSEC, Info, "Not signed", "answers can be forged on the way to a resolver",
			"Turn DNSSEC on at your DNS host, then add the DS record it gives you at your registrar."}}
	case len(ds) == 0:
		return []Check{{AreaDNSSEC, Warn, "Signed, but the registry has no DS record", fmt.Sprintf("%d keys in the zone, none published at the parent", len(keys)),
			"Add the DS record from your DNS host at your registrar; until then nobody validates the signatures."}}
	case len(keys) == 0:
		return []Check{{AreaDNSSEC, Bad, "The registry has a DS record but the zone has no keys", fmt.Sprintf("%d DS records for %s", len(ds), trim(zone)),
			"Validating resolvers (most of the internet) now refuse the whole domain. Remove the DS at your registrar, or turn DNSSEC back on at the DNS host."}}
	}

	// Does any DS match a key?
	matched := ""
	digests := map[uint8]bool{}
	for _, d := range ds {
		if len(d.Raw) < 5 {
			continue
		}
		tag, dt := binary.BigEndian.Uint16(d.Raw), d.Raw[3]
		digests[dt] = true
		want := hex.EncodeToString(d.Raw[4:])
		for _, k := range keys {
			if keyTag(k.Raw) == tag && dsDigest(zone, k.Raw, dt) == want {
				matched = fmt.Sprintf("key %d, %s", tag, digestNames[dt])
			}
		}
	}
	if matched == "" {
		var tags []string
		for _, d := range ds {
			if len(d.Raw) >= 2 {
				tags = append(tags, fmt.Sprint(binary.BigEndian.Uint16(d.Raw)))
			}
		}
		var have []string
		for _, k := range keys {
			have = append(have, fmt.Sprint(keyTag(k.Raw)))
		}
		return append(cs, Check{AreaDNSSEC, Bad, "The DS record doesn't match any key", "DS for key " + strings.Join(tags, ", ") + "; the zone has keys " + strings.Join(have, ", "),
			"Validating resolvers refuse the whole domain. Replace the DS at your registrar with the one your DNS host shows now (this happens after a key change)."})
	}

	// Validation as the world sees it.
	val, err := ask(ctx, zone, dnsx.TypeSOA, true)
	switch {
	case err != nil:
	case val.AD:
		cs = append(cs, Check{AreaDNSSEC, OK, "Signed, and the chain validates", matched, ""})
	case val.Rcode == dnsx.RcodeServFail:
		cs = append(cs, Check{AreaDNSSEC, Bad, "Signatures don't validate", "resolvers answer SERVFAIL for " + trim(zone),
			"The domain is unreachable for most users. Check the signatures at your DNS host, or remove the DS at the registrar until it's fixed."})
	default:
		cs = append(cs, Check{AreaDNSSEC, Warn, "Signed, but the resolver didn't confirm it", matched, ""})
	}

	// Algorithms.
	algs := map[uint8]bool{}
	for _, k := range keys {
		if len(k.Raw) > 3 {
			algs[k.Raw[3]] = true
		}
	}
	var algList []uint8
	for a := range algs {
		algList = append(algList, a)
	}
	sort.Slice(algList, func(i, j int) bool { return algList[i] < algList[j] })
	for _, a := range algList {
		switch algStatus(a) {
		case Warn:
			cs = append(cs, Check{AreaDNSSEC, Warn, "Old algorithm: " + dnsx.AlgString(a), "it still works but is being phased out",
				"Roll the keys over to ECDSAP256SHA256 (13) at your DNS host."})
		case Bad:
			cs = append(cs, Check{AreaDNSSEC, Bad, "Deprecated algorithm: " + dnsx.AlgString(a), "validators may treat the zone as unsigned or reject it",
				"Roll the keys over to ECDSAP256SHA256 (13) at your DNS host."})
		}
	}
	if len(digests) == 1 && digests[1] {
		cs = append(cs, Check{AreaDNSSEC, Warn, "The DS record uses SHA-1", "SHA-1 digests are deprecated",
			"Publish a SHA-256 DS record at your registrar instead."})
	}

	// Signatures about to run out: the usual cause of a sudden DNSSEC
	// outage. Zones signed on the fly (Cloudflare, Route 53) carry signatures
	// of a few days that are renewed constantly, so "soon" is relative to how
	// long each signature lives.
	var soonest time.Time
	var life time.Duration
	for _, s := range sigs {
		if len(s.Raw) >= 16 {
			exp := time.Unix(int64(binary.BigEndian.Uint32(s.Raw[8:12])), 0)
			inc := time.Unix(int64(binary.BigEndian.Uint32(s.Raw[12:16])), 0)
			if soonest.IsZero() || exp.Before(soonest) {
				soonest, life = exp, exp.Sub(inc)
			}
		}
	}
	if !soonest.IsZero() {
		left := soonest.Sub(now())
		short := life <= 8*24*time.Hour
		switch {
		case left <= 0:
			cs = append(cs, Check{AreaDNSSEC, Bad, "Signatures have expired", "on " + soonest.UTC().Format("2006-01-02 15:04 UTC"),
				"Re-sign the zone now; whatever signs it automatically has stopped."})
		case short && left < life/8, !short && left < 3*24*time.Hour:
			cs = append(cs, Check{AreaDNSSEC, Warn, "Signatures expire in " + hoursOrDays(left), soonest.UTC().Format("2006-01-02 15:04 UTC"),
				"Check that the zone is re-signed automatically; when the signatures run out the domain fails for most users."})
		case short:
			cs = append(cs, Check{AreaDNSSEC, OK, "Signatures are renewed continuously", fmt.Sprintf("each lasts %s; the next runs out in %s", hoursOrDays(life), hoursOrDays(left)), ""})
		default:
			cs = append(cs, Check{AreaDNSSEC, OK, fmt.Sprintf("Signatures valid for %d more days", int(left.Hours()/24)), "", ""})
		}
	}
	return cs
}

func hoursOrDays(d time.Duration) string {
	if d < 48*time.Hour {
		return fmt.Sprintf("%.0f h", d.Hours())
	}
	return fmt.Sprintf("%.0f days", d.Hours()/24)
}
