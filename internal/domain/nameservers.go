package domain

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/tworjaga/netcheck/internal/dnsx"
)

// openProbe is the name asked to find open resolvers: any name the zone
// isn't authoritative for.
func openProbe(zone string) string {
	if strings.HasSuffix(zone, "example.org.") {
		return "example.net."
	}
	return "example.org."
}

// nameservers asks each of the zone's nameservers for its SOA, and checks
// the set as a whole.
func nameservers(ctx context.Context, zone string, parent []dnsx.NS, noAddr []string) ([]Nameserver, []Check) {
	var cs []Check
	ns := make([]Nameserver, len(parent))
	soas := make([]*dnsx.RR, len(parent))
	open := make([]bool, len(parent))
	var wg sync.WaitGroup
	for i, p := range parent {
		ns[i] = Nameserver{Name: trim(p.Name), Addr: p.Addr}
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := askNS(ctx, p.Addr, zone, dnsx.TypeSOA, false)
			switch {
			case err != nil:
				ns[i].Error = err.Error()
				return
			case res.Msg.Rcode != dnsx.RcodeSuccess:
				ns[i].Error = "answered " + dnsx.RcodeString(res.Msg.Rcode)
				return
			case !res.Msg.AA:
				ns[i].Error = "answered without authority"
				return
			}
			ns[i].RTT = res.RTT
			if s := ofType(res.Msg.Answer, dnsx.TypeSOA); len(s) > 0 {
				soas[i] = &s[0]
				if f := strings.Fields(s[0].Data); len(f) == 7 {
					v, _ := strconv.ParseUint(f[2], 10, 32)
					ns[i].Serial = uint32(v)
				}
			}
			// Does it also resolve other names for anyone?
			q := dnsx.Query{Name: openProbe(zone), Type: dnsx.TypeA, Recursion: true}
			if o, err := exchange(ctx, dnsx.Server{Addr: net.JoinHostPort(p.Addr, "53"), Transport: dnsx.UDP}, q, queryTimeout); err == nil {
				open[i] = o.Msg.RA && o.Msg.Rcode == dnsx.RcodeSuccess && len(o.Msg.Answer) > 0
			}
		}()
	}
	wg.Wait()

	total := len(parent) + len(noAddr)
	switch {
	case total == 1:
		cs = append(cs, Check{AreaNS, Bad, "Only one nameserver", trim(parent[0].Name),
			"Add a second nameserver, ideally on another network: when the only one is down, the whole domain is gone."})
	default:
		var list []string
		for _, n := range ns {
			list = append(list, n.Name)
		}
		cs = append(cs, Check{AreaNS, OK, fmt.Sprintf("%d nameservers", total), strings.Join(append(list, noAddr...), ", "), ""})
	}
	for _, n := range noAddr {
		cs = append(cs, Check{AreaNS, Bad, trim(n) + " has no address", "it's in the delegation but its name doesn't resolve",
			"Fix the nameserver's A record, or remove it from the delegation at your registrar."})
	}

	var lame []string
	answered := 0
	for _, n := range ns {
		if n.Error != "" {
			lame = append(lame, n.Name+" ("+n.Error+")")
		} else {
			answered++
		}
	}
	if len(lame) > 0 {
		st := Warn
		if answered == 0 {
			st = Bad
		}
		cs = append(cs, Check{AreaNS, st, fmt.Sprintf("%d of %d nameservers don't answer for the zone", len(lame), len(ns)), strings.Join(lame, "; "),
			"Fix them or take them out of the delegation at your registrar: resolvers waste time on them, and lose the domain when the rest fail."})
	} else if len(ns) > 0 {
		cs = append(cs, Check{AreaNS, OK, "Every nameserver answers with authority", "", ""})
	}

	// Network diversity: one /24 (or one /48) for all of them is one outage.
	nets := map[string]bool{}
	for _, n := range ns {
		if ip := net.ParseIP(n.Addr); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				nets[v4.Mask(net.CIDRMask(24, 32)).String()+"/24"] = true
			} else {
				nets[ip.Mask(net.CIDRMask(48, 128)).String()+"/48"] = true
			}
		}
	}
	if len(ns) > 1 && len(nets) == 1 {
		var only string
		for k := range nets {
			only = k
		}
		cs = append(cs, Check{AreaNS, Warn, "All nameservers are in one network", only,
			"Use nameservers in different networks (most DNS hosts give you that), so one outage or attack doesn't take the domain down."})
	}

	// Serials: every nameserver should serve the same version of the zone.
	// Zones run by two providers at once (github.com: AWS and NSONE) keep a
	// serial per provider, so only a difference within one provider counts.
	serials := map[uint32][]string{}
	byProvider := map[string]map[uint32]bool{}
	for _, n := range ns {
		if n.Error == "" && n.Serial != 0 {
			serials[n.Serial] = append(serials[n.Serial], n.Name)
			p := provider(n.Name)
			if byProvider[p] == nil {
				byProvider[p] = map[uint32]bool{}
			}
			byProvider[p][n.Serial] = true
		}
	}
	if len(serials) > 1 {
		var parts []string
		for s, who := range serials {
			parts = append(parts, fmt.Sprintf("%d on %s", s, strings.Join(who, ", ")))
		}
		sort.Strings(parts)
		split := false
		for _, set := range byProvider {
			split = split || len(set) > 1
		}
		if split {
			cs = append(cs, Check{AreaNS, Warn, "Nameservers serve different versions of the zone", strings.Join(parts, "; "),
				"Check that zone transfers to the secondaries work; until they catch up, resolvers get different answers."})
		} else {
			cs = append(cs, Check{AreaNS, Info, fmt.Sprintf("%d DNS providers, each with its own serial", len(byProvider)), strings.Join(parts, "; "), ""})
		}
	}

	// The registry's list (the delegation) and the zone's own NS records
	// should match.
	if answered > 0 {
		for _, n := range ns {
			if n.Error != "" {
				continue
			}
			res, err := askNS(ctx, n.Addr, zone, dnsx.TypeNS, false)
			if err != nil || res.Msg.Rcode != dnsx.RcodeSuccess {
				break
			}
			child := map[string]bool{}
			for _, rr := range ofType(res.Msg.Answer, dnsx.TypeNS) {
				child[strings.ToLower(rr.Data)] = true
			}
			par := map[string]bool{}
			for _, p := range parent {
				par[strings.ToLower(p.Name)] = true
			}
			for _, x := range noAddr {
				par[strings.ToLower(x)] = true
			}
			var onlyParent, onlyChild []string
			for p := range par {
				if !child[p] {
					onlyParent = append(onlyParent, p)
				}
			}
			for c := range child {
				if !par[c] {
					onlyChild = append(onlyChild, c)
				}
			}
			sort.Strings(onlyParent)
			sort.Strings(onlyChild)
			if len(onlyParent)+len(onlyChild) > 0 {
				var d []string
				if len(onlyParent) > 0 {
					d = append(d, "only at the registry: "+names(onlyParent))
				}
				if len(onlyChild) > 0 {
					d = append(d, "only in the zone: "+names(onlyChild))
				}
				cs = append(cs, Check{AreaNS, Warn, "The registry and the zone list different nameservers", strings.Join(d, "; "),
					"Make the NS records in the zone and the nameservers set at your registrar the same list."})
			}
			break
		}
	}

	var openNS []string
	for i, o := range open {
		if o {
			openNS = append(openNS, ns[i].Name)
		}
	}
	if len(openNS) > 0 {
		cs = append(cs, Check{AreaNS, Bad, "Open resolver: " + strings.Join(openNS, ", "), "it looks up any name for anyone, not just your zone",
			"Turn recursion off on authoritative nameservers (BIND: recursion no;). Open resolvers get abused for DDoS amplification."})
	}

	for i := range soas {
		if soas[i] != nil {
			cs = append(cs, soaChecks(*soas[i])...)
			break
		}
	}
	return ns, cs
}

func human(sec uint64) string {
	switch {
	case sec >= 86400 && sec%86400 == 0:
		return fmt.Sprintf("%d d", sec/86400)
	case sec >= 3600 && sec%3600 == 0:
		return fmt.Sprintf("%d h", sec/3600)
	case sec >= 60 && sec%60 == 0:
		return fmt.Sprintf("%d min", sec/60)
	}
	return fmt.Sprintf("%d s", sec)
}

// soaChecks looks at the SOA timers against the usual ranges (RFC 1912,
// RIPE-203).
func soaChecks(soa dnsx.RR) []Check {
	f := strings.Fields(soa.Data)
	if len(f) != 7 {
		return nil
	}
	v := make([]uint64, 5)
	for i := range v {
		v[i], _ = strconv.ParseUint(f[2+i], 10, 32)
	}
	serial, refresh, retry, expire, minimum := v[0], v[1], v[2], v[3], v[4]
	var cs []Check
	var odd []string
	if refresh < 1200 || refresh > 86400 {
		odd = append(odd, "refresh "+human(refresh)+" (usual: 20 min to 1 d)")
	}
	if retry >= refresh || retry < 120 {
		odd = append(odd, "retry "+human(retry)+" (usual: under refresh, 2 min or more)")
	}
	if expire < 604800 || expire > 2419200 {
		odd = append(odd, "expire "+human(expire)+" (usual: 1 to 4 weeks)")
	}
	if minimum < 60 || minimum > 86400 {
		odd = append(odd, "negative-cache time "+human(minimum)+" (usual: 1 min to 1 d)")
	}
	detail := fmt.Sprintf("serial %d · primary %s · contact %s", serial, trim(f[0]), contact(f[1]))
	if len(odd) == 0 {
		cs = append(cs, Check{AreaSOA, OK, "Timers are sensible", detail + fmt.Sprintf(" · refresh %s, retry %s, expire %s, negative %s", human(refresh), human(retry), human(expire), human(minimum)), ""})
	} else {
		// The timers only steer secondaries that copy the zone by transfer;
		// hosted DNS that syncs its own way often sets them freely.
		cs = append(cs, Check{AreaSOA, Info, "Unusual SOA timers", strings.Join(odd, "; ") + "; this matters only if secondaries copy the zone by zone transfer",
			"If they do: refresh 1 h-1 d, retry 15 min-2 h, expire 2-4 weeks, negative-cache time 5 min-1 h."})
		cs = append(cs, Check{AreaSOA, Info, "SOA", detail, ""})
	}
	return cs
}

// provider is a rough name for who runs a nameserver: the label before
// the top-level domain, without numbering ("ns-520.awsdns-01.net" and
// "ns-421.awsdns-52.com" are both "awsdns").
func provider(host string) string {
	labels := strings.Split(trim(strings.ToLower(host)), ".")
	if len(labels) < 2 {
		return host
	}
	l := labels[len(labels)-2]
	if len(labels) >= 3 && len(l) <= 3 { // co.uk, com.au
		l = labels[len(labels)-3]
	}
	if i := strings.LastIndex(l, "-"); i > 0 && strings.Trim(l[i+1:], "0123456789") == "" {
		l = l[:i]
	}
	return strings.TrimRight(l, "0123456789")
}

// contact turns the SOA's rname (hostmaster.example.com.) into an address.
func contact(rname string) string {
	rname = trim(rname)
	// The first unescaped dot is the @.
	for i := 0; i < len(rname); i++ {
		if rname[i] == '\\' {
			i++
			continue
		}
		if rname[i] == '.' {
			return strings.ReplaceAll(rname[:i], `\.`, ".") + "@" + rname[i+1:]
		}
	}
	return rname
}
