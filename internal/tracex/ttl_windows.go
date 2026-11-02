package tracex

import (
	"net"
	"syscall"
	"time"
)

// ttlControl sets the IP TTL on a socket before it connects.
func ttlControl(ttl int) func(network, address string, c syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		if err := c.Control(func(fd uintptr) {
			serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		}); err != nil {
			return err
		}
		return serr
	}
}

var procIsUserAnAdmin = syscall.NewLazyDLL("shell32.dll").NewProc("IsUserAnAdmin")

// elevated reports whether this process runs as administrator. Without it,
// Windows still opens a raw socket but never delivers anything to it.
func elevated() bool {
	if procIsUserAnAdmin.Find() != nil {
		return false
	}
	r, _, _ := procIsUserAnAdmin.Call()
	return r != 0
}

// platformProber: Windows hears routers' replies only on a raw socket,
// which needs a terminal opened as administrator.
func platformProber(proto string, dst net.IP, port int, timeout time.Duration) (prober, string, error) {
	if !elevated() {
		return nil, "", ErrPrivileged
	}
	p, err := newRawProber(proto, dst, port, timeout)
	if err != nil {
		return nil, "", err
	}
	return p, "raw", nil
}
