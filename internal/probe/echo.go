package probe

import (
	"errors"
	"net"
	"time"
)

// EchoKind classifies the answer to one ICMP echo request.
type EchoKind int

const (
	EchoTimeout     EchoKind = iota // nothing came back in time
	EchoOK                          // echo reply from the target
	EchoTTLExceeded                 // a router on the way answered "time exceeded"
	EchoTooBig                      // packet needs fragmenting but DF was set
	EchoUnreachable                 // network or host unreachable
)

// EchoReply is the result of one echo request.
type EchoReply struct {
	Kind EchoKind
	From net.IP // who answered (the target, or the router for TTLExceeded)
	RTT  time.Duration
}

// EchoOpts tunes one echo request.
type EchoOpts struct {
	TTL     int  // 0 = OS default
	Size    int  // payload bytes (0 = 32)
	DF      bool // set the Don't Fragment bit
	Timeout time.Duration
}

// Echoer sends single ICMP echo requests without administrator rights:
// IcmpSendEcho on Windows, unprivileged ping sockets on Linux and macOS.
type Echoer interface {
	Echo(dst net.IP, o EchoOpts) (EchoReply, error)
}

// ErrNoICMP means ICMP isn't usable here (no permission, or unsupported).
var ErrNoICMP = errors.New("icmp unavailable")

// openEchoer is swapped out in tests.
var openEchoer = newPlatformEchoer

// ICMPAvailable reports whether ICMP echo can be used on this machine.
func ICMPAvailable() bool {
	e, err := openEchoer()
	return err == nil && e != nil
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func echoPacket(id, seq uint16, size int) []byte {
	if size <= 0 {
		size = 32
	}
	p := make([]byte, 8+size)
	p[0] = 8 // echo request
	p[4], p[5] = byte(id>>8), byte(id)
	p[6], p[7] = byte(seq>>8), byte(seq)
	for i := 8; i < len(p); i++ {
		p[i] = byte('a' + (i-8)%23)
	}
	c := checksum(p)
	p[2], p[3] = byte(c>>8), byte(c)
	return p
}
