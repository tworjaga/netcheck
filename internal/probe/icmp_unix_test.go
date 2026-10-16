//go:build !windows

package probe

import "testing"

func TestParseICMPReply(t *testing.T) {
	reply := []byte{0, 0, 0, 0, 0x6e, 0x63, 0, 7, 'a'}
	if k, _, ok := parseICMPReply(reply, 7); !ok || k != EchoOK {
		t.Errorf("linux-style reply not parsed")
	}
	if _, _, ok := parseICMPReply(reply, 8); ok {
		t.Errorf("wrong sequence must not match")
	}
	ip := append([]byte{0x45, 0, 0, 29, 0, 0, 0, 0, 64, 1, 0, 0, 1, 1, 1, 1, 10, 0, 0, 2}, reply...)
	if k, src, ok := parseICMPReply(ip, 7); !ok || k != EchoOK || src.String() != "1.1.1.1" {
		t.Errorf("macos-style reply not parsed: %v %v %v", k, src, ok)
	}
	te := []byte{11, 0, 0, 0, 0, 0, 0, 0}
	if k, _, ok := parseICMPReply(te, 1); !ok || k != EchoTTLExceeded {
		t.Errorf("time exceeded not parsed")
	}
}
