package probe

import (
	"context"
	"testing"
	"time"
)

const netshInterfaces = `
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    State                  : connected
    SSID                   : HomeNet
    BSSID                  : AA:BB:CC:11:22:33
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Band                   : 5 GHz
    Channel                : 44
    Receive rate (Mbps)    : 866.7
    Transmit rate (Mbps)   : 866.7
    Signal                 : 82%
`

const netshNetworks = `
SSID 1 : HomeNet
    Network type            : Infrastructure
    BSSID 1                 : aa:bb:cc:11:22:33
         Signal             : 82%
         Radio type         : 802.11ax
         Band               : 5 GHz
         Channel            : 44
SSID 2 : Neighbor1
    BSSID 1                 : de:ad:be:ef:00:01
         Signal             : 70%
         Band               : 5 GHz
         Channel            : 44
SSID 3 : Neighbor2
    BSSID 1                 : de:ad:be:ef:00:02
         Signal             : 60%
         Band               : 2.4 GHz
         Channel            : 6
SSID 4 : Faint
    BSSID 1                 : de:ad:be:ef:00:03
         Signal             : 8%
         Band               : 5 GHz
         Channel            : 44
`

func TestParseNetsh(t *testing.T) {
	info := parseNetshInterfaces(netshInterfaces)
	if !info.Connected || info.SSID != "HomeNet" || info.Channel != 44 || info.Band != "5 GHz" || info.SignalPct != 82 || info.SignalDBm != -59 || info.RateMbps != 866.7 {
		t.Fatalf("got %+v", info)
	}
	nets := parseNetshNetworks(netshNetworks)
	if len(nets) != 4 || nets[1].SSID != "Neighbor1" || nets[1].Channel != 44 || nets[2].Band != "2.4 GHz" {
		t.Fatalf("got %+v", nets)
	}
}

func TestParseNetshGerman(t *testing.T) {
	info := parseNetshInterfaces("    Name : WLAN\n    SSID : Heim\n    Kanal : 6\n    Signal : 70%\n    Funktyp : 802.11n\n")
	if info.SSID != "Heim" || info.Channel != 6 || info.SignalPct != 70 || info.Band != "2.4 GHz" {
		t.Fatalf("got %+v", info)
	}
}

func TestParseNetshDisconnected(t *testing.T) {
	info := parseNetshInterfaces("    Name : Wi-Fi\n    State : disconnected\n")
	if !info.Available || info.Connected {
		t.Fatalf("got %+v", info)
	}
}

func TestChannelAnalysis(t *testing.T) {
	info := parseNetshInterfaces(netshInterfaces)
	info.Neighbors = parseNetshNetworks(netshNetworks)
	info.Analyze()
	// Neighbor1 is strong on 44; Faint (8% = -96 dBm) is too weak to count;
	// our own BSSID must not count against us.
	if info.Sharing != 1 || info.Crowding != "quiet" {
		t.Fatalf("got sharing=%d crowding=%q", info.Sharing, info.Crowding)
	}
}

func TestCrowdedChannelSuggestsBetterOne(t *testing.T) {
	w := WifiInfo{Connected: true, Band: "2.4 GHz", Channel: 6, BSSID: "me"}
	for i := 0; i < 7; i++ {
		w.Neighbors = append(w.Neighbors, WifiNet{BSSID: string(rune('a' + i)), Band: "2.4 GHz", Channel: 6, SignalDBm: -60})
	}
	w.Neighbors = append(w.Neighbors, WifiNet{BSSID: "z", Band: "2.4 GHz", Channel: 1, SignalDBm: -80})
	w.Analyze()
	if w.Crowding != "crowded" || w.BestChan != 11 {
		t.Fatalf("got %+v", w)
	}
}

func TestParseNmcli(t *testing.T) {
	out := "yes:HomeNet:AA\\:BB\\:CC\\:11\\:22\\:33:36:5180 MHz:78:540 Mbit/s\n" +
		"no:Other:DE\\:AD\\:BE\\:EF\\:00\\:01:36:5180 MHz:55:130 Mbit/s\n" +
		"no:Old:DE\\:AD\\:BE\\:EF\\:00\\:02:6:2437 MHz:40:54 Mbit/s\n"
	info := parseNmcli(out)
	if !info.Connected || info.SSID != "HomeNet" || info.BSSID != "aa:bb:cc:11:22:33" || info.Channel != 36 || info.Band != "5 GHz" || info.SignalDBm != -61 {
		t.Fatalf("got %+v", info)
	}
	if len(info.Neighbors) != 2 || info.Neighbors[1].Band != "2.4 GHz" {
		t.Fatalf("neighbors: %+v", info.Neighbors)
	}
}

func TestParseIw(t *testing.T) {
	out := "Connected to aa:bb:cc:11:22:33 (on wlp2s0)\n\tSSID: HomeNet\n\tfreq: 5180\n\tsignal: -58 dBm\n\trx bitrate: 866.7 MBit/s\n"
	info := parseIwLink(out)
	if !info.Connected || info.SSID != "HomeNet" || info.Channel != 36 || info.SignalDBm != -58 || info.BSSID != "aa:bb:cc:11:22:33" {
		t.Fatalf("got %+v", info)
	}
	if got := parseIwLink("Not connected."); got.Connected {
		t.Fatalf("got %+v", got)
	}
}

const sysProfiler = `Wi-Fi:

      Software Versions:
          CoreWLAN: 16.0
      Interfaces:
        en0:
          Card Type: Wi-Fi
          Status: Connected
          Current Network Information:
            HomeNet:
              PHY Mode: 802.11ax
              Channel: 36 (5GHz, 80MHz)
              Transmit Rate: 866
              Signal / Noise: -55 dBm / -92 dBm
          Other Local Wi-Fi Networks:
            Neighbor:
              PHY Mode: 802.11n
              Channel: 6 (2GHz, 20MHz)
              Signal / Noise: -70 dBm / -92 dBm
            Another:
              PHY Mode: 802.11ac
              Channel: 36 (5GHz, 80MHz)
              Signal / Noise: -62 dBm / -92 dBm
`

func TestParseSystemProfiler(t *testing.T) {
	info := parseSystemProfiler(sysProfiler)
	if !info.Connected || info.SSID != "HomeNet" || info.Channel != 36 || info.Band != "5 GHz" || info.SignalDBm != -55 || info.Radio != "802.11ax" || info.Interface != "en0" {
		t.Fatalf("got %+v", info)
	}
	if len(info.Neighbors) != 2 || info.Neighbors[0].SSID != "Neighbor" || info.Neighbors[0].Band != "2.4 GHz" || info.Neighbors[1].Channel != 36 {
		t.Fatalf("neighbors: %+v", info.Neighbors)
	}
}

func TestSystemProfilerRedactedName(t *testing.T) {
	info := parseSystemProfiler("      Interfaces:\n        en0:\n          Current Network Information:\n            <redacted>:\n              Channel: 6 (2GHz, 20MHz)\n              Signal / Noise: -60 dBm / -90 dBm\n")
	if info.SSID != "" || info.Note == "" || info.SignalDBm != -60 {
		t.Fatalf("got %+v", info)
	}
}

func TestSignalQuality(t *testing.T) {
	cases := map[int]string{0: "unknown", -50: "excellent", -65: "good", -70: "fair", -80: "weak", -90: "very weak"}
	for d, want := range cases {
		if got := SignalQuality(d); got != want {
			t.Errorf("SignalQuality(%d) = %s, want %s", d, got, want)
		}
	}
}

func TestSampleSignal(t *testing.T) {
	seq := []int{-60, -62, -70}
	i := 0
	read := func(context.Context) WifiInfo {
		v := seq[i%len(seq)]
		i++
		return WifiInfo{Connected: true, SignalDBm: v}
	}
	var got []int
	out := SampleSignal(context.Background(), time.Millisecond, 3, read, func(d int) { got = append(got, d) })
	if len(out) != 3 || out[2] != -70 || len(got) != 3 {
		t.Fatalf("got %v %v", out, got)
	}
}
