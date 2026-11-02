package probe

import (
	"context"
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"time"
)

// MDNSDevice is what multicast DNS told us about one address.
type MDNSDevice struct {
	IP       net.IP
	Hostname string   // without the ".local" suffix
	Services []string // service types such as "googlecast" or "ipp"
}

// mdnsGroup is the mDNS multicast address; tests point it at localhost.
var mdnsGroup = "224.0.0.251:5353"

// commonServices are asked for directly, in addition to the generic
// "what services exist?" query.
var commonServices = []string{
	"_workstation._tcp", "_airplay._tcp", "_raop._tcp", "_googlecast._tcp", "_ipp._tcp",
	"_printer._tcp", "_hap._tcp", "_homekit._tcp", "_spotify-connect._tcp", "_smb._tcp",
	"_afpovertcp._tcp", "_ssh._tcp", "_http._tcp", "_companion-link._tcp", "_sleep-proxy._udp",
}

// mdnsQuery builds a question with the unicast-response bit set, so devices
// answer straight back to our ephemeral port. That means no need to join the
// multicast group or bind port 5353 (which may need privileges or clash with
// the OS's own responder).
func mdnsQuery(name string, qtype uint16) []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = appendName(b, name)
	b = binary.BigEndian.AppendUint16(b, qtype)
	return binary.BigEndian.AppendUint16(b, 0x8001) // IN + unicast-response
}

func stripLocal(s string) string {
	s = strings.TrimSuffix(s, ".")
	return strings.TrimSuffix(s, ".local")
}

func serviceType(s string) string {
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimSuffix(s, ".local")
	s = strings.TrimSuffix(strings.TrimSuffix(s, "._tcp"), "._udp")
	return strings.TrimPrefix(s, "_")
}

// MDNSScan multicasts service queries for about dur and returns what
// answered. No elevation needed.
func MDNSScan(ctx context.Context, dur time.Duration) []MDNSDevice {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil
	}
	defer pc.Close()
	dst, err := net.ResolveUDPAddr("udp4", mdnsGroup)
	if err != nil {
		return nil
	}
	send := func(names ...string) {
		for _, n := range names {
			_, _ = pc.WriteTo(mdnsQuery(n, TypePTR), dst)
		}
	}
	send("_services._dns-sd._udp.local.")
	for _, s := range commonServices {
		send(s + ".local.")
	}

	hostIP := map[string]net.IP{}     // "tv.local." -> address
	instHost := map[string]string{}   // instance -> host from SRV
	instType := map[string][]string{} // instance -> service types from PTR
	srcHost := map[string]string{}    // fallback: source address -> host
	asked := map[string]bool{}
	deadline := time.Now().Add(dur)
	buf := make([]byte, 9000)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		_ = pc.SetReadDeadline(deadline)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		m, err := ParseMsg(buf[:n])
		if err != nil || !m.Response {
			continue
		}
		var src net.IP
		if ua, ok := from.(*net.UDPAddr); ok {
			src = ua.IP
		}
		for _, rr := range m.Answers {
			switch rr.Type {
			case TypeA:
				if rr.IP != nil {
					hostIP[strings.ToLower(rr.Name)] = rr.IP
				}
			case TypeSRV:
				instHost[rr.Name] = strings.ToLower(rr.Host)
			case TypePTR:
				if strings.HasPrefix(rr.Name, "_services._dns-sd") {
					// A service type exists on the network: ask who offers it.
					if t := rr.Host; !asked[t] {
						asked[t] = true
						send(t)
					}
					continue
				}
				instType[rr.Host] = append(instType[rr.Host], serviceType(rr.Name))
				if src != nil {
					if h, ok := instHost[rr.Host]; ok {
						srcHost[src.String()] = h
					}
				}
			}
		}
	}

	byIP := map[string]*MDNSDevice{}
	get := func(ip net.IP) *MDNSDevice {
		d := byIP[ip.String()]
		if d == nil {
			d = &MDNSDevice{IP: ip}
			byIP[ip.String()] = d
		}
		return d
	}
	for h, ip := range hostIP {
		get(ip).Hostname = stripLocal(h)
	}
	for inst, types := range instType {
		host := instHost[inst]
		ip, ok := hostIP[host]
		if !ok {
			continue
		}
		d := get(ip)
		d.Services = append(d.Services, types...)
	}
	var out []MDNSDevice
	for _, d := range byIP {
		sort.Strings(d.Services)
		d.Services = dedupe(d.Services)
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.String() < out[j].IP.String() })
	return out
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
