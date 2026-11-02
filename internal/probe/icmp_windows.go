//go:build windows

package probe

import (
	"net"
	"syscall"
	"time"
	"unsafe"
)

// Windows exposes ICMP to ordinary users through iphlpapi.dll, so no
// administrator rights (and no raw sockets) are needed.
var (
	iphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procIcmpCreateFile  = iphlpapi.NewProc("IcmpCreateFile")
	procIcmpCloseHandle = iphlpapi.NewProc("IcmpCloseHandle")
	procIcmpSendEcho    = iphlpapi.NewProc("IcmpSendEcho")
)

// IP_STATUS values from ipexport.h.
const (
	ipSuccess         = 0
	ipDestNetUnreach  = 11002
	ipDestHostUnreach = 11003
	ipPacketTooBig    = 11009
	ipReqTimedOut     = 11010
	ipTTLExpiredTrans = 11013
	ipTTLExpiredReasm = 11014
	ipFlagDF          = 0x02
)

type ipOptionInformation struct {
	TTL         uint8
	TOS         uint8
	Flags       uint8
	OptionsSize uint8
	OptionsData uintptr
}

type icmpEchoReply struct {
	Address       uint32
	Status        uint32
	RoundTripTime uint32
	DataSize      uint16
	Reserved      uint16
	Data          uintptr
	Options       ipOptionInformation
}

type winEchoer struct{}

func newPlatformEchoer() (Echoer, error) {
	if err := iphlpapi.Load(); err != nil {
		return nil, ErrNoICMP
	}
	if err := procIcmpSendEcho.Find(); err != nil {
		return nil, ErrNoICMP
	}
	return winEchoer{}, nil
}

func (winEchoer) Echo(dst net.IP, o EchoOpts) (EchoReply, error) {
	ip4 := dst.To4()
	if ip4 == nil {
		return EchoReply{}, ErrNoICMP
	}
	h, _, _ := procIcmpCreateFile.Call()
	if h == 0 || h == ^uintptr(0) {
		return EchoReply{}, ErrNoICMP
	}
	defer procIcmpCloseHandle.Call(h)

	size := o.Size
	if size <= 0 {
		size = 32
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte('a' + i%23)
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	opts := ipOptionInformation{TTL: 128}
	if o.TTL > 0 {
		opts.TTL = uint8(o.TTL)
	}
	if o.DF {
		opts.Flags = ipFlagDF
	}
	buf := make([]byte, int(unsafe.Sizeof(icmpEchoReply{}))+size+8+128)
	addr := uint32(ip4[0]) | uint32(ip4[1])<<8 | uint32(ip4[2])<<16 | uint32(ip4[3])<<24

	start := time.Now()
	n, _, callErr := procIcmpSendEcho.Call(
		h,
		uintptr(addr),
		uintptr(unsafe.Pointer(&payload[0])),
		uintptr(uint16(size)),
		uintptr(unsafe.Pointer(&opts)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(uint32(len(buf))),
		uintptr(uint32(timeout/time.Millisecond)),
	)
	rtt := time.Since(start)
	r := (*icmpEchoReply)(unsafe.Pointer(&buf[0]))
	if n == 0 {
		if en, ok := callErr.(syscall.Errno); ok {
			switch en {
			case ipPacketTooBig:
				return EchoReply{Kind: EchoTooBig}, nil
			case ipDestNetUnreach, ipDestHostUnreach:
				return EchoReply{Kind: EchoUnreachable}, nil
			case ipTTLExpiredTrans, ipTTLExpiredReasm:
				// Some Windows builds report "time exceeded" as a failed
				// call; the router's address is still in the reply buffer.
				if r.Address != 0 {
					from := net.IPv4(byte(r.Address), byte(r.Address>>8), byte(r.Address>>16), byte(r.Address>>24))
					return EchoReply{Kind: EchoTTLExceeded, From: from, RTT: rtt}, nil
				}
			}
		}
		return EchoReply{Kind: EchoTimeout}, nil
	}
	from := net.IPv4(byte(r.Address), byte(r.Address>>8), byte(r.Address>>16), byte(r.Address>>24))
	reply := EchoReply{From: from, RTT: time.Duration(r.RoundTripTime) * time.Millisecond}
	if r.RoundTripTime == 0 {
		reply.RTT = rtt // sub-millisecond: use our own clock
	}
	switch r.Status {
	case ipSuccess:
		reply.Kind = EchoOK
	case ipTTLExpiredTrans, ipTTLExpiredReasm:
		reply.Kind = EchoTTLExceeded
	case ipPacketTooBig:
		reply.Kind = EchoTooBig
	case ipDestNetUnreach, ipDestHostUnreach:
		reply.Kind = EchoUnreachable
	default:
		reply.Kind = EchoTimeout
	}
	return reply, nil
}
