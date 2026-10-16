package probe

import (
	"context"
	"net"
	"time"
)

const icmpTimeout = 1500 * time.Millisecond

// PingICMP sends count echo requests (0 = until ctx is cancelled). It
// returns ErrNoICMP when ICMP can't be used so callers can fall back to TCP.
func PingICMP(ctx context.Context, host string, count int, interval time.Duration, onSample func(ms float64)) (PingResult, error) {
	res := PingResult{Target: host, Method: "icmp"}
	ip, err := resolve(ctx, host)
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	res.Addr = ip
	dst := net.ParseIP(ip)
	if dst.To4() == nil {
		return res, ErrNoICMP
	}
	e, err := openEchoer()
	if err != nil {
		return res, err
	}
	for i := 0; count == 0 || i < count; i++ {
		r, err := e.Echo(dst, EchoOpts{Timeout: icmpTimeout})
		if err != nil {
			if res.Sent == 0 {
				return res, err
			}
			r = EchoReply{}
		}
		if ctx.Err() != nil {
			break
		}
		res.Sent++
		ms := -1.0
		if r.Kind == EchoOK {
			ms = float64(r.RTT.Microseconds()) / 1000
			res.Received++
		}
		res.SamplesMs = append(res.SamplesMs, ms)
		if onSample != nil {
			onSample(ms)
		}
		if count != 0 && i == count-1 {
			break
		}
		sleep(ctx, interval)
	}
	res.finish()
	return res, nil
}

// PingBest prefers true ICMP and quietly falls back to TCP connects when
// ICMP isn't available or is filtered. The reason lands in Note so the UI
// can mention it in one dim line.
func PingBest(ctx context.Context, host string, tcpPorts []int, count int, interval time.Duration, onSample func(ms float64)) PingResult {
	if ICMPAvailable() {
		ip, err := resolve(ctx, host)
		if err != nil {
			return PingResult{Target: host, Method: "icmp", Error: err.Error()}
		}
		if dst := net.ParseIP(ip); dst.To4() != nil && icmpAnswers(ctx, dst) {
			if res, err := PingICMP(ctx, host, count, interval, onSample); err == nil {
				return res
			}
		}
		if ctx.Err() != nil {
			return PingResult{Target: host, Addr: ip, Method: "icmp", Error: "interrupted"}
		}
		res := PingAuto(ctx, host, tcpPorts, count, interval, onSample)
		if res.Received > 0 {
			res.Note = "no reply to ICMP; measured with TCP instead"
		} else {
			res.Note = "no reply to ICMP or TCP"
		}
		return res
	}
	res := PingAuto(ctx, host, tcpPorts, count, interval, onSample)
	res.Note = "ICMP isn't available here without elevation; measured with TCP instead"
	return res
}

func icmpAnswers(ctx context.Context, dst net.IP) bool {
	e, err := openEchoer()
	if err != nil {
		return false
	}
	for i := 0; i < 2 && ctx.Err() == nil; i++ {
		if r, err := e.Echo(dst, EchoOpts{Timeout: 800 * time.Millisecond}); err == nil && r.Kind == EchoOK {
			return true
		}
	}
	return false
}
