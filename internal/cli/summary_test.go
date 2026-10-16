package cli

import (
	"strings"
	"testing"
)

func TestSummaryHidesThePublicIP(t *testing.T) {
	s := &summary{local: "192.168.1.20", gateway: "192.168.1.1", public: "198.51.100.41", isp: "Example ISP (AS64496)", nat: "CGNAT"}
	if got := s.String(); !strings.Contains(got, "198.51.100.41 · Example ISP") {
		t.Errorf("shown: %s", got)
	}
	t.Setenv("NETCHECK_HIDE_IP", "1")
	got := s.String()
	if strings.Contains(got, "198.51.100.41") || strings.Contains(got, "Example ISP") || !strings.Contains(got, "public IP hidden · CGNAT") {
		t.Errorf("hidden: %s", got)
	}
}
