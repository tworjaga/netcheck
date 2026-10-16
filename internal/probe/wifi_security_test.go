package probe

import "testing"

func TestWifiSecurity(t *testing.T) {
	en := `    Name                   : Wi-Fi
    State                  : connected
    SSID                   : TP-Link
    AP BSSID               : ec:75:0c:a7:a4:de
    Connected Akm-cipher   : [ akm = 00-0f-ac:02, cipher =  00-0f-ac:04 ]
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Signal                 : 90%
`
	if i := parseNetshInterfaces(en); i.Security != "WPA2-Personal" || i.Cipher != "CCMP" {
		t.Errorf("english: %q %q", i.Security, i.Cipher)
	}
	de := `    Name                   : WLAN
    SSID                   : Zuhause
    Authentifizierung      : WPA3-Personal
    Verschlüsselung        : GCMP
    Signal                 : 80%
`
	if i := parseNetshInterfaces(de); i.Security != "WPA3-Personal" || i.Cipher != "GCMP" {
		t.Errorf("german: %q %q", i.Security, i.Cipher)
	}
	if i := parseNmcli("yes:Home:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:2437:70:130 Mbit/s:WPA2\n"); i.Security != "WPA2" {
		t.Errorf("nmcli: %q", i.Security)
	}
	if i := parseNmcli("yes:Cafe:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:2437:70:130 Mbit/s:\n"); i.Security != "Open" {
		t.Errorf("nmcli open: %q", i.Security)
	}
	mac := `Wi-Fi:
  Interfaces:
    en0:
      Current Network Information:
        Home:
          PHY Mode: 802.11ax
          Channel: 36 (5GHz, 80MHz)
          Security: WPA2 Personal
          Signal / Noise: -55 dBm / -90 dBm
`
	if i := parseSystemProfiler(mac); i.Security != "WPA2 Personal" {
		t.Errorf("mac: %q", i.Security)
	}
}
