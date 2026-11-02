package probe

import (
	"strings"
	"testing"
)

// Fixtures in the layout Windows 11 prints. CRLF line endings are kept on
// purpose: that's what netsh, arp and tracert write.

const netshWin11Interfaces = "\r\n" +
	"There is 1 interface on the system: \r\n" +
	"\r\n" +
	"    Name                   : Wi-Fi\r\n" +
	"    Description            : Intel(R) Wi-Fi 6E AX211 160MHz\r\n" +
	"    GUID                   : 3c1f7e92-5b1a-4d55-9a0e-7a2c1b8f0d11\r\n" +
	"    Physical address       : a4:6b:b6:01:02:03\r\n" +
	"    Interface type         : Primary\r\n" +
	"    State                  : connected\r\n" +
	"    SSID                   : HomeNet\r\n" +
	"    AP BSSID               : aa:bb:cc:11:22:33\r\n" +
	"    Band                   : 5 GHz\r\n" +
	"    Channel                : 44\r\n" +
	"    Network type           : Infrastructure\r\n" +
	"    Radio type             : 802.11ax\r\n" +
	"    Authentication         : WPA2-Personal\r\n" +
	"    Cipher                 : CCMP\r\n" +
	"    Connection mode        : Auto Connect\r\n" +
	"    Receive rate (Mbps)    : 1201\r\n" +
	"    Transmit rate (Mbps)   : 1201\r\n" +
	"    Signal                 : 92%\r\n" +
	"    Profile                : HomeNet\r\n" +
	"    QoS MSCS Configured         : 0\r\n" +
	"    QoS Map Configured          : 0\r\n" +
	"    QoS Map Allowed by Policy   : 0\r\n" +
	"\r\n" +
	"    Hosted network status  : Not available\r\n"

const netshWin11Networks = "\r\n" +
	"Interface name : Wi-Fi \r\n" +
	"There are 2 networks currently visible. \r\n" +
	"\r\n" +
	"SSID 1 : HomeNet\r\n" +
	"    Network type            : Infrastructure\r\n" +
	"    Authentication          : WPA2-Personal\r\n" +
	"    Encryption              : CCMP \r\n" +
	"    BSSID 1                 : aa:bb:cc:11:22:33\r\n" +
	"         Signal             : 92%  \r\n" +
	"         Radio type         : 802.11ax\r\n" +
	"         Band               : 5 GHz\r\n" +
	"         Channel            : 44 \r\n" +
	"         Bss Load:  \r\n" +
	"             Connected Stations:        2\r\n" +
	"             Channel Utilization:        13 (5 %)\r\n" +
	"             Medium Available Capacity: 31250\r\n" +
	"         Basic rates (Mbps) : 6 12 24\r\n" +
	"         Other rates (Mbps) : 9 18 36 48 54\r\n" +
	"SSID 2 : Neighbor\r\n" +
	"    Network type            : Infrastructure\r\n" +
	"    Authentication          : WPA3-Personal\r\n" +
	"    Encryption              : CCMP \r\n" +
	"    BSSID 1                 : de:ad:be:ef:00:01\r\n" +
	"         Signal             : 64%  \r\n" +
	"         Radio type         : 802.11ac\r\n" +
	"         Band               : 5 GHz\r\n" +
	"         Channel            : 44 \r\n" +
	"         Bss Load:  \r\n" +
	"             Connected Stations:        7\r\n" +
	"             Channel Utilization:        201 (78 %)\r\n" +
	"             Medium Available Capacity: 0\r\n"

func TestNetshWindows11APBSSID(t *testing.T) {
	info := parseNetshInterfaces(netshWin11Interfaces)
	if !info.Connected || info.BSSID != "aa:bb:cc:11:22:33" || info.Channel != 44 || info.SignalPct != 92 || info.Band != "5 GHz" || info.RateMbps != 1201 || info.Interface != "Wi-Fi" {
		t.Fatalf("got %+v", info)
	}
	// Our own access point must not count as a neighbour on our channel.
	info.Neighbors = parseNetshNetworks(netshWin11Networks)
	info.Analyze()
	if info.Sharing != 1 {
		t.Fatalf("own AP counted against us: sharing=%d", info.Sharing)
	}
}

func TestNetshBssLoadDoesNotOverwriteChannel(t *testing.T) {
	nets := parseNetshNetworks(netshWin11Networks)
	if len(nets) != 2 || nets[0].Channel != 44 || nets[1].Channel != 44 || nets[0].SignalPct != 92 || nets[1].SignalPct != 64 {
		t.Fatalf("got %+v", nets)
	}
}

func TestNetshOEMCodePage(t *testing.T) {
	// Spanish Windows piped through CP850: "Señal" has 0xA4 for ñ,
	// "Velocidad de recepción" has 0xA2 for ó. Not valid UTF-8.
	out := "    Nombre                 : Wi-Fi\r\n" +
		"    SSID                   : Casa\r\n" +
		"    BSSID                  : aa:bb:cc:11:22:33\r\n" +
		"    Banda                  : 2,4 GHz\r\n" +
		"    Canal                  : 6\r\n" +
		"    Velocidad de recepci\xa2n (Mbps)    : 144,4\r\n" +
		"    Se\xa4al                  : 70%\r\n"
	info := parseNetshInterfaces(out)
	if !info.Available || info.SSID != "Casa" || info.SignalPct != 70 || info.Channel != 6 || info.Band != "2.4 GHz" || info.RateMbps != 144.4 {
		t.Fatalf("got %+v", info)
	}
}

func TestNetshUnknownLanguageFallsBackOnValues(t *testing.T) {
	// Keys we have no translation for (Russian here) still yield signal and
	// band from the shape of the values.
	out := "    Имя                    : Беспроводная сеть\r\n" +
		"    GUID                   : 3c1f7e92-5b1a-4d55-9a0e-7a2c1b8f0d11\r\n" +
		"    SSID                   : Dom\r\n" +
		"    Диапазон               : 5 ГГц\r\n" +
		"    Сигнал                 : 81%\r\n"
	info := parseNetshInterfaces(out)
	if !info.Available || !info.Connected || info.SignalPct != 81 {
		t.Fatalf("got %+v", info)
	}
}

func TestParseARPWindowsMultipleInterfaces(t *testing.T) {
	out := strings.ReplaceAll(`
Interface: 192.168.1.23 --- 0xb
  Internet Address      Physical Address      Type
  192.168.1.1           a4-2b-b0-12-34-56     dynamic
  192.168.1.40          3c-22-fb-aa-bb-cc     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  239.255.255.250       01-00-5e-7f-ff-fa     static
  255.255.255.255       ff-ff-ff-ff-ff-ff     static

Interface: 172.27.96.1 --- 0x2f
  Internet Address      Physical Address      Type
  172.27.111.255        ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
`, "\n", "\r\n")
	got := ParseARP(out)
	if len(got) != 2 || got[0].MAC != "a4:2b:b0:12:34:56" || got[1].IP.String() != "192.168.1.40" {
		t.Fatalf("got %+v", got)
	}
}

func TestParseTracertWindows(t *testing.T) {
	out := strings.ReplaceAll(`
Tracing route to 1.1.1.1 over a maximum of 30 hops

  1    <1 ms    <1 ms    <1 ms  192.168.1.1
  2     8 ms     7 ms     9 ms  100.64.0.1
  3     *        *        *     Request timed out.
  4     *       14 ms    13 ms  172.68.1.1
  5    12 ms    11 ms    12 ms  1.1.1.1

Trace complete.
`, "\n", "\r\n")
	hops := parseHopLines(out)
	if len(hops) != 5 {
		t.Fatalf("want 5 hops, got %+v", hops)
	}
	if hops[0].IP != "192.168.1.1" || hops[0].AvgMs != 0.5 {
		t.Fatalf("hop 1: %+v", hops[0])
	}
	if hops[2].IP != "" || hops[2].Sent != 1 || hops[2].Received != 0 {
		t.Fatalf("hop 3 should be silent: %+v", hops[2])
	}
	if hops[3].IP != "172.68.1.1" || hops[3].AvgMs != 14 {
		t.Fatalf("hop 4: %+v", hops[3])
	}
	if hops[4].IP != "1.1.1.1" {
		t.Fatalf("hop 5: %+v", hops[4])
	}
}

// Captured from a real Windows 11 laptop (Intel AX203); SSID and addresses
// replaced. Note the "Rssi" line, which netsh only prints on newer builds.
const netshWin11RealInterfaces = "\r\n" +
	"There is 1 interface on the system: \r\n" +
	"\r\n" +
	"    Name                   : Wi-Fi\r\n" +
	"    Description            : Intel(R) Wi-Fi 6 AX203\r\n" +
	"    GUID                   : 00000000-0000-0000-0000-000000000000\r\n" +
	"    Physical address       : 02:00:00:00:00:01\r\n" +
	"    Interface type         : Primary\r\n" +
	"    State                  : connected\r\n" +
	"    SSID                   : HomeNet\r\n" +
	"    AP BSSID               : aa:bb:cc:11:22:33\r\n" +
	"    Band                   : 2.4 GHz\r\n" +
	"    Channel                : 1\r\n" +
	"    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher =  00-0f-ac:04 ]\r\n" +
	"    Network type           : Infrastructure\r\n" +
	"    Radio type             : 802.11n\r\n" +
	"    Authentication         : WPA2-Personal\r\n" +
	"    Cipher                 : CCMP\r\n" +
	"    Connection mode        : Auto Connect\r\n" +
	"    Receive rate (Mbps)    : 130\r\n" +
	"    Transmit rate (Mbps)   : 72.2\r\n" +
	"    Signal                 : 81% \r\n" +
	"    Rssi                   : -64\r\n" +
	"    Profile                : HomeNet \r\n" +
	"    QoS MSCS Configured         : 0\r\n" +
	"    QoS Map Configured          : 0\r\n" +
	"    QoS Map Allowed by Policy   : 0\r\n" +
	"\r\n"

func TestNetshUsesRssiWhenPrinted(t *testing.T) {
	info := parseNetshInterfaces(netshWin11RealInterfaces)
	// 81% would convert to -60 dBm; the adapter's own reading is -64.
	if info.SignalDBm != -64 || info.SignalPct != 81 || info.Channel != 1 || info.Band != "2.4 GHz" || info.BSSID != "aa:bb:cc:11:22:33" || info.RateMbps != 130 {
		t.Fatalf("got %+v", info)
	}
}

func TestOwnAccessPointIsNotANeighbour(t *testing.T) {
	// A real `wifi --json` listed the connected AP among its neighbours.
	info := parseNetshInterfaces(netshWin11Interfaces)
	info.Neighbors = parseNetshNetworks(netshWin11Networks)
	info.Analyze()
	for _, n := range info.Neighbors {
		if n.BSSID == info.BSSID {
			t.Fatalf("own AP %s listed as a neighbour: %+v", info.BSSID, info.Neighbors)
		}
	}
	if len(info.Neighbors) != 1 || info.Neighbors[0].SSID != "Neighbor" || info.Sharing != 1 {
		t.Fatalf("got %+v", info)
	}
}
