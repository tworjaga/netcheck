package probe

import (
	"context"
	"errors"
	"net"
	"time"
)

// MTUResult is what don't-fragment probing found.
type MTUResult struct {
	Target string `json:"target"`
	Addr   string `json:"addr,omitempty"`
	// MTU is the largest IP packet that got through unfragmented (payload +
	// 28 bytes of IPv4 and ICMP headers). 0 means it couldn't be measured.
	MTU int `json:"mtu"`
	// Signalled is true when an oversized packet was refused with a "too
	// big" message, as it should be. When big packets just vanish instead,
	// that's a path-MTU black hole: some sites hang after connecting.
	Signalled bool   `json:"too_big_signalled"`
	Probes    int    `json:"probes"`
	Error     string `json:"error,omitempty"`
}

// ErrICMPBlocked means even a small ping got no answer.
var ErrICMPBlocked = errors.New("no reply to ping")

const (
	mtuHeaders = 28   // 20 IPv4 + 8 ICMP
	mtuMax     = 1500 // Ethernet
	mtuMin     = 576  // the smallest MTU IPv4 guarantees
)

// fits sends a DF ping of the given total packet size twice (so one lost
// packet isn't mistaken for "too big"). It reports whether one got through
// and whether a "too big" answer came back.
func fits(ctx context.Context, e Echoer, dst net.IP, size int) (ok, tooBig bool) {
	for try := 0; try < 2 && ctx.Err() == nil; try++ {
		r, err := e.Echo(dst, EchoOpts{Size: size - mtuHeaders, DF: true, Timeout: 1200 * time.Millisecond})
		if err != nil {
			continue
		}
		switch r.Kind {
		case EchoOK:
			return true, false
		case EchoTooBig:
			return false, true // definitive: no point retrying
		}
	}
	return false, false
}

// ProbeMTU binary-searches the path MTU to host with don't-fragment pings.
func ProbeMTU(ctx context.Context, host string) MTUResult {
	res := MTUResult{Target: host}
	ip, err := resolve(ctx, host)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Addr = ip
	dst := net.ParseIP(ip)
	if dst.To4() == nil {
		res.Error = "MTU probing supports IPv4 destinations only"
		return res
	}
	e, err := openEchoer()
	if err != nil {
		res.Error = ErrNoICMP.Error()
		return res
	}
	if ok, _ := fits(ctx, e, dst, 84); !ok {
		res.Error = ErrICMPBlocked.Error()
		return res
	}
	res.Probes++
	if ok, big := fits(ctx, e, dst, mtuMax); ok {
		res.Probes++
		res.MTU = mtuMax
		return res
	} else if big {
		res.Signalled = true
	}
	res.Probes++
	lo, hi := mtuMin, mtuMax // lo fits (assumed), hi doesn't
	if ok, big := fits(ctx, e, dst, lo); !ok {
		res.Signalled = res.Signalled || big
		res.Error = "even small unfragmented packets don't get through"
		return res
	}
	for hi-lo > 1 && ctx.Err() == nil {
		mid := (lo + hi) / 2
		ok, big := fits(ctx, e, dst, mid)
		res.Probes++
		if ok {
			lo = mid
		} else {
			hi = mid
			res.Signalled = res.Signalled || big
		}
	}
	if ctx.Err() != nil {
		res.Error = "interrupted"
		return res
	}
	res.MTU = lo
	return res
}
