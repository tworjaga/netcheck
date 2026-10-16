package probe

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseARPWindows(t *testing.T) {
	out := "Interface: 192.168.1.20 --- 0x7\n  Internet Address      Physical Address      Type\n" +
		"  192.168.1.1           aa-bb-cc-11-22-33     dynamic\n" +
		"  192.168.1.255         ff-ff-ff-ff-ff-ff     static\n" +
		"  224.0.0.22            01-00-5e-00-00-16     static\n"
	got := ParseARP(out)
	if len(got) != 1 || got[0].IP.String() != "192.168.1.1" || got[0].MAC != "aa:bb:cc:11:22:33" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseARPMac(t *testing.T) {
	out := "? (192.168.1.1) at a:b:c:1:2:3 on en0 ifscope [ethernet]\n? (192.168.1.77) at (incomplete) on en0 ifscope [ethernet]\n"
	got := ParseARP(out)
	if len(got) != 1 || got[0].MAC != "0a:0b:0c:01:02:03" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseProcARP(t *testing.T) {
	out := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"192.168.1.1      0x1         0x2         aa:bb:cc:11:22:33     *        eth0\n" +
		"192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
	got := ParseProcARP(out)
	if len(got) != 1 || got[0].IP.String() != "192.168.1.1" {
		t.Fatalf("incomplete entries must be skipped, got %+v", got)
	}
}

func TestVendorAndRandomMAC(t *testing.T) {
	if Vendor("b8:27:eb:00:00:01") != "Raspberry Pi" || Vendor("B8-27-EB-00-00-01") != "Raspberry Pi" {
		t.Error("Raspberry Pi prefix not recognised")
	}
	if Vendor("12:34:56:00:00:01") != "" {
		t.Error("unknown prefix should have no vendor")
	}
	if !IsRandomMAC("da:a1:19:00:00:01") || IsRandomMAC("b8:27:eb:00:00:01") {
		t.Error("locally-administered bit misread")
	}
	for k := range ouiTable {
		if len(k) != 6 || k != strings.ToUpper(k) || strings.Trim(k, "0123456789ABCDEF") != "" {
			t.Errorf("malformed OUI key %q", k)
		}
	}
}

func TestHostsAndNarrowing(t *testing.T) {
	_, n, _ := net.ParseCIDR("192.168.1.0/24")
	h := Hosts(n)
	if len(h) != 254 || h[0].String() != "192.168.1.1" || h[253].String() != "192.168.1.254" {
		t.Fatalf("got %d hosts %v..%v", len(h), h[0], h[len(h)-1])
	}
	_, big, _ := net.ParseCIDR("10.1.2.0/16")
	if ones, _ := narrowSubnet(&net.IPNet{IP: net.ParseIP("10.1.2.3"), Mask: big.Mask}).Mask.Size(); ones != 24 {
		t.Fatalf("a /16 should be narrowed to /24, got /%d", ones)
	}
}

// mdnsFake answers every query with a Chromecast-style record set.
func mdnsFake(t *testing.T) func() {
	t.Helper()
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			_, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			b := []byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0}
			rr := func(name string, typ byte, rdata []byte) {
				b = appendName(b, name)
				b = append(b, 0, typ, 0x80, 1, 0, 0, 0, 120, 0, byte(len(rdata)))
				b = append(b, rdata...)
			}
			rr("_googlecast._tcp.local.", TypePTR, appendName(nil, "Den TV._googlecast._tcp.local."))
			rr("Den TV._googlecast._tcp.local.", TypeSRV, append([]byte{0, 0, 0, 0, 0x1f, 0x49}, appendName(nil, "tv.local.")...))
			rr("tv.local.", TypeA, []byte{192, 0, 2, 3})
			_, _ = pc.WriteTo(b, from)
		}
	}()
	old := mdnsGroup
	mdnsGroup = pc.LocalAddr().String()
	return func() { mdnsGroup = old; pc.Close() }
}

func TestMDNSScan(t *testing.T) {
	defer mdnsFake(t)()
	got := MDNSScan(context.Background(), 400*time.Millisecond)
	if len(got) != 1 || got[0].IP.String() != "192.0.2.3" || got[0].Hostname != "tv" || len(got[0].Services) != 1 || got[0].Services[0] != "googlecast" {
		t.Fatalf("got %+v", got)
	}
}

func TestDiscoverDevicesMergesSources(t *testing.T) {
	defer mdnsFake(t)()
	oldSSDP := ssdpGroup
	silent, _ := net.ListenPacket("udp4", "127.0.0.1:0")
	ssdpGroup = silent.LocalAddr().String()
	oldARP, oldPoke, oldRev := readARP, pokeUDP, reverseLookup
	readARP = func(context.Context) []ARPEntry {
		return []ARPEntry{{IP: ip("192.0.2.1"), MAC: "aa:bb:cc:11:22:33"}, {IP: ip("192.0.2.5"), MAC: "da:a1:19:00:00:05"}, {IP: ip("203.0.113.9"), MAC: "aa:aa:aa:aa:aa:aa"}}
	}
	pokeUDP = func(context.Context, []net.IP) {}
	reverseLookup = func(_ context.Context, a string) string {
		if a == "192.0.2.1" {
			return "fritz.box"
		}
		return ""
	}
	defer func() { ssdpGroup, readARP, pokeUDP, reverseLookup = oldSSDP, oldARP, oldPoke, oldRev; silent.Close() }()
	withEchoer(t, &fakeEcho{script: []float64{4}}, nil)

	_, sub, _ := net.ParseCIDR("192.0.2.0/29")
	res := DiscoverDevices(context.Background(), ip("192.0.2.2"), ip("192.0.2.1"), sub, ScanOptions{MDNSWait: 400 * time.Millisecond, SSDPWait: 100 * time.Millisecond})
	by := map[string]Device{}
	for _, d := range res.Devices {
		by[d.IP] = d
	}
	if _, outside := by["203.0.113.9"]; outside {
		t.Error("an ARP entry outside the subnet must be ignored")
	}
	if gw := by["192.0.2.1"]; !gw.Gateway || gw.Name != "fritz.box" || gw.Kind != "router" || gw.MAC == "" {
		t.Errorf("gateway: %+v", gw)
	}
	if tv := by["192.0.2.3"]; tv.Name != "tv" || tv.Kind != "Chromecast / Google speaker" {
		t.Errorf("mdns device: %+v", tv)
	}
	if ph := by["192.0.2.5"]; !ph.RandomMAC || ph.Vendor != "" {
		t.Errorf("random-MAC device: %+v", ph)
	}
	if !by["192.0.2.2"].Self || res.Note != "" {
		t.Errorf("self/note: %+v %q", by["192.0.2.2"], res.Note)
	}
	if len(res.Devices) < 2 || !ipLess(res.Devices[0].IP, res.Devices[1].IP) {
		t.Errorf("devices should be sorted by address: %+v", res.Devices)
	}
}

func TestDiscoverDevicesWithoutICMPSaysSo(t *testing.T) {
	withEchoer(t, nil, ErrNoICMP)
	oldARP, oldPoke := readARP, pokeUDP
	readARP = func(context.Context) []ARPEntry { return nil }
	pokeUDP = func(context.Context, []net.IP) {}
	defer func() { readARP, pokeUDP = oldARP, oldPoke }()
	_, sub, _ := net.ParseCIDR("192.0.2.0/29")
	res := DiscoverDevices(context.Background(), nil, nil, sub, ScanOptions{MDNSWait: 50 * time.Millisecond, SSDPWait: 50 * time.Millisecond})
	if res.Note == "" {
		t.Fatal("expected a one-line note when ICMP is unavailable")
	}
}
