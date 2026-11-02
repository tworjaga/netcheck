//go:build !windows && !linux

package tracex

import (
	"net"
	"time"
)

// platformProber: macOS and the BSDs hear routers' replies only on a raw
// socket, which needs root.
func platformProber(proto string, dst net.IP, port int, timeout time.Duration) (prober, string, error) {
	p, err := newRawProber(proto, dst, port, timeout)
	if err != nil {
		return nil, "", err
	}
	return p, "raw", nil
}
