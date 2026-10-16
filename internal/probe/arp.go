package probe

import (
	"context"
	"net"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// ARPEntry is one neighbour the OS has already talked to.
type ARPEntry struct {
	IP  net.IP
	MAC string // lower-case aa:bb:cc:dd:ee:ff
}

var (
	reARPWin   = regexp.MustCompile(`^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b`)
	reARPMac   = regexp.MustCompile(`\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})\b`)
	reARPLinux = regexp.MustCompile(`^(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+(0x[0-9a-fA-F]+)\s+([0-9a-fA-F:]{17})\s`)
)

// normMAC pads each octet (macOS prints "a:b:c") and uses lower-case colons.
func normMAC(s string) string {
	s = strings.ReplaceAll(strings.ToLower(s), "-", ":")
	parts := strings.Split(s, ":")
	for i, p := range parts {
		if len(p) == 1 {
			parts[i] = "0" + p
		}
	}
	return strings.Join(parts, ":")
}

func usableNeighbour(ip net.IP, mac string) bool {
	if ip == nil || mac == "" || mac == "ff:ff:ff:ff:ff:ff" || mac == "00:00:00:00:00:00" {
		return false
	}
	if ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return false
	}
	return !strings.HasPrefix(mac, "01:00:5e") // IPv4 multicast MACs
}

func addARP(out *[]ARPEntry, ipStr, mac string) {
	ip := net.ParseIP(ipStr)
	mac = normMAC(mac)
	if usableNeighbour(ip, mac) {
		*out = append(*out, ARPEntry{IP: ip, MAC: mac})
	}
}

// ParseARP reads `arp -a` output from Windows or macOS/BSD.
func ParseARP(out string) []ARPEntry {
	var res []ARPEntry
	for _, ln := range strings.Split(out, "\n") {
		if m := reARPWin.FindStringSubmatch(ln); m != nil {
			addARP(&res, m[1], m[2])
		} else if m := reARPMac.FindStringSubmatch(ln); m != nil {
			addARP(&res, m[1], m[2])
		}
	}
	return res
}

// ParseProcARP reads Linux's /proc/net/arp, skipping incomplete entries.
func ParseProcARP(out string) []ARPEntry {
	var res []ARPEntry
	for _, ln := range strings.Split(out, "\n") {
		m := reARPLinux.FindStringSubmatch(ln + " ")
		if m == nil || m[2] == "0x0" {
			continue
		}
		addARP(&res, m[1], m[3])
	}
	return res
}

// readARP returns the OS neighbour table. Replaced in tests.
var readARP = func(ctx context.Context) []ARPEntry {
	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/net/arp"); err == nil {
			return ParseProcARP(string(b))
		}
	}
	out, _ := Run(ctx, 5*time.Second, "arp", "-a")
	return ParseARP(out)
}

// MACOf returns the MAC address the OS has for ip, or "" if it has none.
func MACOf(ctx context.Context, ip net.IP) string {
	for _, e := range readARP(ctx) {
		if e.IP.Equal(ip) {
			return e.MAC
		}
	}
	return ""
}

// ARPTable returns the devices the OS has talked to recently (its neighbour
// table), without sending anything.
func ARPTable(ctx context.Context) []ARPEntry { return readARP(ctx) }
