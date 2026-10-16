package probe

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// PingResult summarizes a series of latency probes.
//
// Probes are TCP connects, which work without root on every OS. A refused
// connection still counts as a reply, because the host answered with a reset;
// only timeouts and unreachable errors count as loss.
type PingResult struct {
	Target    string    `json:"target"`
	Addr      string    `json:"addr,omitempty"`
	Method    string    `json:"method"`
	Sent      int       `json:"sent"`
	Received  int       `json:"received"`
	LossPct   float64   `json:"loss_pct"`
	MinMs     float64   `json:"min_ms"`
	AvgMs     float64   `json:"avg_ms"`
	MaxMs     float64   `json:"max_ms"`
	JitterMs  float64   `json:"jitter_ms"`
	SamplesMs []float64 `json:"samples_ms"`
	Note      string    `json:"note,omitempty"` // e.g. why TCP was used instead of ICMP
	Error     string    `json:"error,omitempty"`
}

func isRefused(err error) bool {
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "refused")
}

func probeTCP(ctx context.Context, addr string, timeout time.Duration) (time.Duration, bool) {
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	c, err := d.DialContext(ctx, "tcp", addr)
	rtt := time.Since(start)
	if err == nil {
		c.Close()
		return rtt, true
	}
	if isRefused(err) {
		return rtt, true
	}
	return 0, false
}

func sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

func resolve(ctx context.Context, host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		ips, err = net.DefaultResolver.LookupIP(ctx, "ip", host)
	}
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("could not resolve %s", host)
	}
	return ips[0].String(), nil
}

// Ping probes host:port count times (0 = until ctx is cancelled), calling
// onSample with each round-trip time in ms, or -1 for a lost probe.
func Ping(ctx context.Context, host string, port, count int, interval time.Duration, onSample func(ms float64)) PingResult {
	res := PingResult{Target: host, Method: "tcp:" + strconv.Itoa(port)}
	ip, err := resolve(ctx, host)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Addr = ip
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	for i := 0; count == 0 || i < count; i++ {
		rtt, ok := probeTCP(ctx, addr, 1500*time.Millisecond)
		if ctx.Err() != nil {
			break // interrupted mid-probe: don't count it as loss
		}
		res.Sent++
		ms := -1.0
		if ok {
			ms = float64(rtt.Microseconds()) / 1000
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
	return res
}

// PingAuto finds the first port in ports that answers, then runs a full
// Ping on it. Useful for routers, which may only listen on a few ports.
// If nothing answers it returns a 100% loss result without a long wait.
func PingAuto(ctx context.Context, host string, ports []int, count int, interval time.Duration, onSample func(ms float64)) PingResult {
	ip, err := resolve(ctx, host)
	if err != nil {
		return PingResult{Target: host, Method: "tcp", Error: err.Error()}
	}
	for _, p := range ports {
		addr := net.JoinHostPort(ip, strconv.Itoa(p))
		for try := 0; try < 2; try++ {
			if _, ok := probeTCP(ctx, addr, 700*time.Millisecond); ok {
				return Ping(ctx, host, p, count, interval, onSample)
			}
			if ctx.Err() != nil {
				return PingResult{Target: host, Addr: ip, Method: "tcp", Error: "interrupted"}
			}
		}
	}
	n := len(ports) * 2
	res := PingResult{Target: host, Addr: ip, Method: "tcp", Sent: n}
	for i := 0; i < n; i++ {
		res.SamplesMs = append(res.SamplesMs, -1)
	}
	res.finish()
	return res
}

func (r *PingResult) finish() {
	if r.Sent > 0 {
		r.LossPct = float64(r.Sent-r.Received) / float64(r.Sent) * 100
	}
	var sum, jitterSum float64
	prev := -1.0
	jitterN := 0
	r.MinMs = math.Inf(1)
	for _, v := range r.SamplesMs {
		if v < 0 {
			continue
		}
		sum += v
		r.MinMs = math.Min(r.MinMs, v)
		r.MaxMs = math.Max(r.MaxMs, v)
		if prev >= 0 {
			jitterSum += math.Abs(v - prev)
			jitterN++
		}
		prev = v
	}
	if r.Received == 0 {
		r.MinMs = 0
		return
	}
	r.AvgMs = sum / float64(r.Received)
	if jitterN > 0 {
		r.JitterMs = jitterSum / float64(jitterN)
	}
}
