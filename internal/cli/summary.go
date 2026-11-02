package cli

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/tworjaga/netcheck/internal/probe"
)

// summary builds the dim line above the menu. The local part is instant; the
// public IP, ISP and NAT status fill in a moment later, so the menu never
// waits on the network.
type summary struct {
	mu               sync.Mutex
	local, gateway   string
	public, isp, nat string
	offline          bool
}

func startSummary() *summary {
	s := &summary{}
	if ip := probe.LocalIP(); ip != nil {
		s.local = ip.String()
	}
	gw, gwErr := probe.DefaultGateway()
	if gwErr == nil {
		s.gateway = gw.String()
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		pub, err := probe.PublicIP(ctx)
		if err != nil {
			s.set(func() { s.offline = true })
			return
		}
		s.set(func() { s.public = pub.String() })
		info := probe.LookupASN(ctx, pub)
		s.set(func() { s.isp = ispLabel(info) })
		if gwErr == nil {
			n := probe.DetectNAT(ctx, gw, pub, nil)
			s.set(func() { s.nat = natLabel(n) })
		}
	}()
	return s
}

func (s *summary) set(f func()) {
	s.mu.Lock()
	f()
	s.mu.Unlock()
}

func ispLabel(i probe.IPInfo) string {
	switch {
	case i.ISP != "" && i.ASN != "":
		return i.ISP + " (" + i.ASN + ")"
	case i.ISP != "":
		return i.ISP
	}
	return i.ASN
}

func natLabel(n probe.NATInfo) string {
	switch n.Kind {
	case "cgnat":
		return "CGNAT"
	case "double":
		return "double NAT"
	}
	return ""
}

func (s *summary) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var parts []string
	if s.local != "" {
		parts = append(parts, s.local)
	}
	if s.gateway != "" {
		parts = append(parts, "gateway "+s.gateway)
	}
	switch {
	case s.offline:
		parts = append(parts, "offline")
	case s.public != "" && os.Getenv("NETCHECK_HIDE_IP") != "":
		// For screenshots and screen sharing: no public address, no ISP.
		p := "public IP hidden"
		if s.nat != "" {
			p += " · " + s.nat
		}
		parts = append(parts, p)
	case s.public != "":
		p := s.public
		if s.isp != "" {
			p += " · " + s.isp
		}
		if s.nat != "" {
			p += " · " + s.nat
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "no network detected"
	}
	return strings.Join(parts, "  →  ")
}
