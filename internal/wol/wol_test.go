package wol

import (
	"bytes"
	"errors"
	"net"
	"testing"
)

func TestParseMAC(t *testing.T) {
	for _, in := range []string{"00:11:22:aa:bb:cc", "00-11-22-AA-BB-CC", "0011.22aa.bbcc", "001122aabbcc"} {
		m, err := ParseMAC(in)
		if err != nil || m.String() != "00:11:22:aa:bb:cc" {
			t.Errorf("%s: %v %v", in, m, err)
		}
	}
	for _, bad := range []string{"", "0011223344", "00:11:22:33:44:55:66:77", "zz:11:22:33:44:55"} {
		if _, err := ParseMAC(bad); err == nil {
			t.Errorf("%q should fail", bad)
		}
	}
}

func TestPacket(t *testing.T) {
	mac, _ := ParseMAC("00:11:22:33:44:55")
	p := Packet(mac)
	if len(p) != 102 || !bytes.Equal(p[:6], bytes.Repeat([]byte{0xff}, 6)) {
		t.Fatalf("% x", p[:12])
	}
	for i := 0; i < 16; i++ {
		if !bytes.Equal(p[6+i*6:12+i*6], mac) {
			t.Errorf("copy %d", i)
		}
	}
}

func TestBroadcasts(t *testing.T) {
	_, lan, _ := net.ParseCIDR("192.168.0.200/24")
	lan.IP = net.ParseIP("192.168.0.200").To4()
	_, wide, _ := net.ParseCIDR("10.1.2.3/16")
	wide.IP = net.ParseIP("10.1.2.3").To4()
	lo := &net.IPNet{IP: net.ParseIP("127.0.0.1").To4(), Mask: net.CIDRMask(8, 32)}
	v6 := &net.IPNet{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}
	got := Broadcasts([]*net.IPNet{lan, wide, lo, v6, lan})
	want := []string{"255.255.255.255", "192.168.0.255", "10.1.255.255"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("%v, want %v", got, want)
		}
	}
}

func TestWake(t *testing.T) {
	old := send
	defer func() { send = old }()
	sent := map[string]int{}
	send = func(addr string, b []byte) error {
		if len(b) != 102 {
			t.Errorf("packet length %d", len(b))
		}
		if addr == "10.255.255.255:9" {
			return errors.New("network unreachable")
		}
		sent[addr]++
		return nil
	}
	mac, _ := ParseMAC("00:11:22:33:44:55")
	ok, errs := Wake(mac, []string{"255.255.255.255", "10.255.255.255"}, 9)
	if len(ok) != 1 || ok[0] != "255.255.255.255" || len(errs) != 1 || sent["255.255.255.255:9"] != 3 {
		t.Errorf("ok %v errs %v sent %v", ok, errs, sent)
	}
}
