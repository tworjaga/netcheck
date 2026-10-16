package probe

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
	"time"
)

// SSDPResponse is one device's answer to an M-SEARCH.
type SSDPResponse struct {
	From     net.IP
	Location string
	Server   string
	ST       string
	USN      string
}

// ssdpGroup is the SSDP multicast address; tests point it at localhost.
var ssdpGroup = "239.255.255.250:1900"

// SSDPSearch multicasts an M-SEARCH for st and collects answers for dur.
// No elevation is needed (it uses an ordinary UDP socket).
func SSDPSearch(ctx context.Context, st string, dur time.Duration) ([]SSDPResponse, error) {
	pc, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return nil, err
	}
	defer pc.Close()
	dst, err := net.ResolveUDPAddr("udp4", ssdpGroup)
	if err != nil {
		return nil, err
	}
	req := "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: " + st + "\r\n\r\n"
	for i := 0; i < 2; i++ { // UDP is lossy; ask twice
		_, _ = pc.WriteTo([]byte(req), dst)
		time.Sleep(30 * time.Millisecond)
	}
	deadline := time.Now().Add(dur)
	var out []SSDPResponse
	seen := map[string]bool{}
	buf := make([]byte, 4096)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		_ = pc.SetReadDeadline(deadline)
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		r, ok := parseSSDP(buf[:n])
		if !ok {
			continue
		}
		if ua, isUDP := from.(*net.UDPAddr); isUDP {
			r.From = ua.IP
		}
		if key := r.From.String() + r.USN + r.Location; !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out, nil
}

func parseSSDP(b []byte) (SSDPResponse, bool) {
	resp, err := http.ReadResponse(bufio.NewReader(strings.NewReader(string(b))), nil)
	if err != nil {
		return SSDPResponse{}, false
	}
	defer resp.Body.Close()
	return SSDPResponse{
		Location: resp.Header.Get("Location"),
		Server:   resp.Header.Get("Server"),
		ST:       resp.Header.Get("St"),
		USN:      resp.Header.Get("Usn"),
	}, true
}
