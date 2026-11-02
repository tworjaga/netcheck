//go:build !windows

package probe

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// On Linux and macOS an ICMP "datagram" socket lets unprivileged users send
// echo requests. Linux needs net.ipv4.ping_group_range to include the user's
// group (most distributions allow it); macOS always allows it.
type unixEchoer struct{}

// echoSeq is shared by every echoer so concurrent pings (watch probes the
// router and the internet at once) never reuse a sequence number.
var echoSeq atomic.Uint32

func newPlatformEchoer() (Echoer, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return nil, ErrNoICMP
	}
	_ = syscall.Close(fd)
	return &unixEchoer{}, nil
}

func (unixEchoer) Echo(dst net.IP, o EchoOpts) (EchoReply, error) {
	ip4 := dst.To4()
	if ip4 == nil {
		return EchoReply{}, ErrNoICMP
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_ICMP)
	if err != nil {
		return EchoReply{}, ErrNoICMP
	}
	defer syscall.Close(fd)

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	tv := syscall.NsecToTimeval(int64(timeout))
	_ = syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	if o.TTL > 0 {
		_ = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, o.TTL)
	}
	if o.DF {
		if err := setDF(fd); err != nil {
			return EchoReply{}, ErrNoICMP
		}
	}

	seq := uint16(echoSeq.Add(1))
	pkt := echoPacket(0x6e63, seq, o.Size)
	var to syscall.SockaddrInet4
	copy(to.Addr[:], ip4)
	start := time.Now()
	if err := syscall.Sendto(fd, pkt, 0, &to); err != nil {
		switch {
		case errors.Is(err, syscall.EMSGSIZE):
			return EchoReply{Kind: EchoTooBig}, nil
		case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
			return EchoReply{Kind: EchoUnreachable}, nil
		case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
			return EchoReply{}, ErrNoICMP
		}
		return EchoReply{Kind: EchoTimeout}, nil
	}

	deadline := start.Add(timeout)
	buf := make([]byte, 2048)
	for time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return EchoReply{Kind: EchoTimeout}, nil
		}
		rtt := time.Since(start)
		if k, src, ok := parseICMPReply(buf[:n], seq); ok {
			if sa, isV4 := from.(*syscall.SockaddrInet4); isV4 && src == nil {
				src = net.IP(sa.Addr[:]).To4()
			}
			if k == EchoOK && src != nil && !src.Equal(ip4) {
				continue // macOS hands every socket every reply: not ours
			}
			return EchoReply{Kind: k, From: src, RTT: rtt}, nil
		}
	}
	return EchoReply{Kind: EchoTimeout}, nil
}

// parseICMPReply interprets a datagram from an ICMP socket. macOS prepends
// the IP header; Linux doesn't. The kernel may rewrite the echo ID, so only
// the sequence number is matched.
func parseICMPReply(b []byte, seq uint16) (EchoKind, net.IP, bool) {
	if len(b) > 20 && b[0]>>4 == 4 {
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || len(b) < ihl+8 {
			return 0, nil, false
		}
		src := net.IP(append([]byte(nil), b[12:16]...))
		k, _, ok := parseICMPBody(b[ihl:], seq)
		return k, src, ok
	}
	k, _, ok := parseICMPBody(b, seq)
	return k, nil, ok
}

func parseICMPBody(b []byte, seq uint16) (EchoKind, net.IP, bool) {
	if len(b) < 8 {
		return 0, nil, false
	}
	switch b[0] {
	case 0: // echo reply
		if uint16(b[6])<<8|uint16(b[7]) == seq {
			return EchoOK, nil, true
		}
	case 11:
		return EchoTTLExceeded, nil, true
	case 3:
		if b[1] == 4 {
			return EchoTooBig, nil, true
		}
		return EchoUnreachable, nil, true
	}
	return 0, nil, false
}
